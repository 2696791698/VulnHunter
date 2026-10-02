"""Offline regression for blackboard merging, context isolation and tool recovery.

Run in the devcontainer: python scripts/inspect_agent_isolation.py
No model/MCP traffic; all filesystem checks use temporary directories.
"""
import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import audit_agent as audit
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool

os.environ['LANGSMITH_TRACING'] = 'false'
logging.getLogger('audit_agent').setLevel(logging.CRITICAL)
observations = []


@tool
def fail_once() -> str:
    """Simulate a recoverable container tool failure without contacting Docker."""
    raise RuntimeError('EXPECTED_OFFLINE_FAILURE')


@tool
def large_result() -> str:
    """Return a large offline payload to exercise framework offloading."""
    return 'PAYLOAD ' * 15000


class LargeResultModel(BaseChatModel):
    @property
    def _llm_type(self):
        return 'offline-large-result'

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        replies = [m for m in messages if m.type == 'tool']
        if not replies:
            msg = AIMessage(content='', tool_calls=[{'name': 'large_result', 'args': {}, 'id': 'large_payload'}])
        else:
            assert '/.vulnhunter/large_tool_results/' in str(replies[-1].content)
            msg = AIMessage(content='done')
        return ChatResult(generations=[ChatGeneration(message=msg)])


class ModelFailureProbe(LargeResultModel):
    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if '你的名字叫executor' in str(messages[0].content):
            raise RuntimeError('SIMULATED_UPSTREAM_FAILURE')
        replies = [m for m in messages if m.type == 'tool']
        if not replies:
            msg = AIMessage(content='', tool_calls=[{
                'name': 'task', 'args': {'subagent_type': 'executor', 'description': 'simulate failure'},
                'id': 'model_failure_task',
            }])
        else:
            assert replies[-1].status == 'error'
            assert 'SIMULATED_UPSTREAM_FAILURE' in replies[-1].content
            msg = AIMessage(content='Failure remains explicit; no security verdict inferred.')
        return ChatResult(generations=[ChatGeneration(message=msg)])


class ProbeModel(BaseChatModel):
    @property
    def _llm_type(self):
        return 'offline-isolation-probe'

    def bind_tools(self, tools, **kwargs):
        names = {t.name if hasattr(t, 'name') else t.get('function', t).get('name') for t in tools}
        assert not names.intersection({'write_file', 'edit_file', 'delete', 'execute'})
        if 'append_blackboard' in names:
            assert names == {'append_blackboard', 'fail_once'}
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        child = '你的名字叫executor' in str(messages[0].content)
        replies = [m for m in messages if m.type == 'tool']
        if child:
            label = next(m.content for m in messages if m.type == 'human')
            assert 'PARENT_SECRET' not in str(messages)
            assert '[Blackboard]' not in str(messages[0].content)
            if not replies:
                assert [m.type for m in messages] == ['system', 'human']
                calls = [{'name': 'fail_once', 'args': {}, 'id': 'same_failure_id'}]
            elif len(replies) == 1:
                assert replies[0].status == 'error'
                assert 'EXPECTED_OFFLINE_FAILURE' in replies[0].content
                calls = [{'name': 'append_blackboard', 'args': {'facts': [f'- {label}: recovered'], 'evidence': []}, 'id': 'same_append_id'}]
            else:
                calls = []
                observations.append(label)
            msg = AIMessage(content='' if calls else 'CHILD_FINAL', tool_calls=calls)
        else:
            user = next(m.content for m in messages if m.type == 'human')
            label = user.removeprefix('PARENT_SECRET_')
            if len(replies) < 3:
                # Two parallel children, followed by another child inheriting their events.
                indexes = [0, 1] if not replies else [2]
                calls = [{'name': 'task', 'args': {'subagent_type': 'executor', 'description': f'{label}-{i}'}, 'id': f'task_{i}'} for i in indexes]
                msg = AIMessage(content='', tool_calls=calls)
            else:
                assert all(m.content == 'CHILD_FINAL' for m in replies)
                for i in range(3):
                    assert f'- {label}-{i}: recovered' in str(messages[0].content)
                msg = AIMessage(content='PARENT_FINAL')
        return ChatResult(generations=[ChatGeneration(message=msg)])


async def main():
    async def no_tools():
        return []
    async def fake_tools():
        return [fail_once]
    audit.get_analysis_tools = no_tools
    audit.get_docker_tools = fake_tools
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder) / 'project'
        root.mkdir()
        (root / 'inside.txt').write_text('INSIDE')
        outside = Path(folder) / 'outside.txt'
        outside.write_text('OUTSIDE_SECRET')
        (root / 'escape').symlink_to(outside)
        audit.PROJECT_ROOT = str(root)
        backend = audit.ProjectFilesystemBackend(root_dir=root, virtual_mode=True)
        assert backend._resolve_path(str(root / 'inside.txt')) == root / 'inside.txt'
        assert 'INSIDE' in str(backend.read('/inside.txt'))
        for path in ['/escape', '../outside.txt']:
            try:
                backend._resolve_path(path)
            except ValueError:
                pass
            else:
                raise AssertionError(f'Escaping path accepted: {path}')
        assert 'OUTSIDE_SECRET' not in str(backend.read(str(outside)))
        assert backend.write('/new.txt', 'blocked').error
        assert backend.edit('/inside.txt', 'INSIDE', 'changed').error
        assert backend.delete('/inside.txt').error
        assert backend.upload_files([('/upload.txt', b'blocked')])[0].error
        # Same compiled agent, concurrent requests: no process-global shared blackboard.
        agent = await audit.create_audit_agent(ProbeModel())
        results = await asyncio.gather(*[
            agent.ainvoke({'messages': [('user', 'PARENT_SECRET_' + label)], 'blackboard_events': {}})
            for label in ['A', 'B']
        ])
        for label, result in zip(['A', 'B'], results):
            expected = {f'- {label}-{i}: recovered' for i in range(3)}
            assert set(result['blackboard_text'].splitlines()) == expected
            assert len(result['blackboard_events']) == 3
            assert result['blackboard_text'] == audit.render_blackboard_events(result['blackboard_events'])
            assert len([m for m in result['messages'] if m.type == 'tool']) == 3
        # Replaying existing event snapshots is idempotent; conflicting edits are rejected.
        events = results[0]['blackboard_events']
        assert audit.merge_blackboard_events(events, events) == events
        try:
            audit.merge_blackboard_events(events, {next(iter(events)): {'facts': ['- altered']}})
        except ValueError:
            pass
        else:
            raise AssertionError('Mutable event accepted')
        async def large_tools():
            return [large_result]
        audit.get_analysis_tools = large_tools
        agent = await audit.create_audit_agent(LargeResultModel())
        result = await agent.ainvoke({'messages': [('user', 'exercise offloading')]})
        assert result.get('files'), 'Large result was not saved in graph state'
        assert not (root / '.vulnhunter').exists(), 'Framework wrote artifacts into project'
        assert (root / 'inside.txt').read_text() == 'INSIDE'
        assert {p.name for p in root.iterdir()} == {'inside.txt', 'escape'}
        agent = await audit.create_audit_agent(ModelFailureProbe())
        result = await agent.ainvoke({'messages': [('user', 'exercise model failure')]})
        assert not result.get('blackboard_events'), 'Failure fabricated a confirmed fact'
    print(json.dumps({'passed': True, 'recovered_children': len(observations),
                      'checks': ['parallel event merge', 'sequential snapshot deduplication',
                                 'concurrent run isolation', 'parent/child message isolation',
                                 'executor tool whitelist', 'tool error recovery and status',
                                 'returned blackboard synchronization', 'project path confinement',
                                 'read-only backend', 'large results stored in state only',
                                 'upstream failure returned with error status']}, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
