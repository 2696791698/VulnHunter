import os
from unittest.mock import MagicMock, patch

import pytest

import audit_agent


@pytest.mark.parametrize("failure", [False, True])
def test_audit_run_releases_codebadger_on_terminal_paths(tmp_path, failure):
    client = MagicMock()
    container = client.containers.run.return_value
    container.status = "exited"

    async def fake_audit(*args, **kwargs):
        if failure:
            raise RuntimeError("agent failed")
        return "finished"

    with patch.object(audit_agent.docker, "from_env", return_value=client), patch.object(
        audit_agent, "remove_stale_container"
    ), patch.object(audit_agent, "run_audit_agent", side_effect=fake_audit), patch.object(
        audit_agent, "release_codebadger_job"
    ) as release:
        if failure:
            with pytest.raises(RuntimeError, match="agent failed"):
                audit_agent.run(project_root=str(tmp_path), job_id="audit-one")
        else:
            assert audit_agent.run(project_root=str(tmp_path), job_id="audit-one") == "finished"

    release.assert_called_once_with("audit-one")
    container.remove.assert_called_once_with(force=True)


def test_release_uses_codebadger_http_endpoint():
    response = MagicMock()
    response.__enter__.return_value = response
    with patch.dict(os.environ, {"CodeBadger_URL": "http://127.0.0.1:4242/mcp"}), patch.object(
        audit_agent, "urlopen", return_value=response
    ) as open_url:
        audit_agent.release_codebadger_job("audit-one")

    request = open_url.call_args.args[0]
    assert request.full_url == "http://127.0.0.1:4242/audit-jobs/audit-one/release"
    assert request.get_method() == "POST"


@pytest.mark.asyncio
async def test_codebadger_mcp_calls_carry_audit_job_header(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    captured = {}
    client_options = {}

    class ClientStub:
        def __init__(self, connections, **kwargs):
            captured.update(connections)
            client_options.update(kwargs)

        async def get_tools(self, *, server_name=None):
            return []

    with patch.object(audit_agent, "MultiServerMCPClient", ClientStub):
        assert await audit_agent.get_analysis_tools("audit-one") == []

    assert captured["CodeBadger"]["headers"] == {"X-VulnHunter-Job-ID": "audit-one"}
    assert client_options["tool_interceptors"] == [audit_agent._retry_codebadger_read_tool_call]
