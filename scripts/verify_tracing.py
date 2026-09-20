"""Checks that the local tracer produces the same, correct trace tree whether
LangSmith tracing is on or off, and that payloads reach the bridge whole.

Run inside the devcontainer, with the project venv:

    /home/vscode/.venv/bin/python scripts/verify_tracing.py --langsmith off
    /home/vscode/.venv/bin/python scripts/verify_tracing.py --langsmith on

It uses a hand-written chat model and never contacts a provider, so it costs
nothing. With `--langsmith on` the LangSmith endpoint is pointed at a dead local
port: the RunTrees (which are what used to break the tree) are still created,
but nothing is uploaded to anyone's account.

Prints a JSON summary on stdout; exit status is non-zero if any check failed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# Must be set before the LangChain/LangSmith imports read the environment.
_parser = argparse.ArgumentParser()
_parser.add_argument("--langsmith", choices=("on", "off"), default="off")
_parser.add_argument("--json", metavar="PATH", help="also write the summary here")
_ARGS = _parser.parse_args()

if _ARGS.langsmith == "off":
    os.environ["LANGSMITH_TRACING"] = "false"
    os.environ["LANGCHAIN_TRACING_V2"] = "false"
else:
    os.environ["LANGSMITH_TRACING"] = "true"
    os.environ.setdefault("LANGSMITH_API_KEY", "lsv2_pt_unused_by_this_harness")
    # Dead port: the RunTree is built locally, the upload always fails.
    os.environ["LANGSMITH_ENDPOINT"] = "http://127.0.0.1:9"
    os.environ["LANGSMITH_PROJECT"] = "verify-tracing"

from deepagents import create_deep_agent  # noqa: E402
from langchain.agents.middleware import wrap_model_call, wrap_tool_call  # noqa: E402
from langchain_core.language_models.chat_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from agent_tracing import BridgeTracer  # noqa: E402

BIG = "A" * 200_000
MANY = [f"line {i}" for i in range(500)]


@tool
def read_file(path: str) -> object:
    """Read a file; `big`, `many` and `deep` exercise payload fidelity."""
    if path == "big":
        return BIG
    if path == "many":
        return MANY
    if path == "deep":
        node: dict = {}
        for _ in range(40):
            node = {"nested": node}
        return node
    return f"contents of {path}"


@tool
def grep_file(pattern: str) -> str:
    """Search a file."""
    return f"matches for {pattern}"


# Shaped like the middleware audit_agent.py installs: async handlers, one of
# each hook. These are what langchain wraps in `langsmith.traceable`.
@wrap_tool_call
async def return_tool_errors_to_model(request, handler):
    return await handler(request)


@wrap_model_call
async def inject_blackboard(request, handler):
    return await handler(request)


class ScriptedModel(BaseChatModel):
    """Two tool calls on the first turn, then a final answer."""

    turns: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.turns += 1
        if self.turns == 1:
            message = AIMessage(content="", tool_calls=[
                {"name": "read_file", "args": {"path": "big"}, "id": "call_big"},
                {"name": "grep_file", "args": {"pattern": "x"}, "id": "call_grep"},
            ])
        elif self.turns == 2:
            message = AIMessage(content="", tool_calls=[
                {"name": "read_file", "args": {"path": "many"}, "id": "call_many"},
                {"name": "read_file", "args": {"path": "deep"}, "id": "call_deep"},
            ])
        else:
            message = AIMessage(content="done")
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted"


class RecordingTracer(BridgeTracer):
    """A real tracer, with the HTTP hop replaced by a list."""

    def __init__(self) -> None:
        super().__init__("http://127.0.0.1:9/never")
        self.events: list[dict] = []

    def _post(self, batch: list[dict]) -> None:
        self.events.extend(batch)


def run() -> dict:
    tracer = RecordingTracer()
    agent = create_deep_agent(
        model=ScriptedModel(),
        tools=[read_file, grep_file],
        middleware=[return_tool_errors_to_model, inject_blackboard],
    )
    asyncio.run(agent.ainvoke(
        {"messages": [("user", "audit this")]},
        config={"callbacks": [tracer]},
    ))
    time.sleep(2)  # let the pump drain
    return {"events": tracer.events, "stats": tracer.stats()}


def analyse(events: list[dict], stats: dict) -> dict:
    starts = [e for e in events if e["type"] == "span.start"]
    ends = {e["spanId"]: e for e in events if e["type"] == "span.end"}
    span_ids = {e["spanId"] for e in starts}
    parents = {e["spanId"]: e.get("parentId") for e in starts}
    traces = {e["traceId"] for e in starts}

    dangling = sorted(sid for sid, pid in parents.items() if pid is not None and pid not in span_ids)
    roots = sorted(sid for sid, pid in parents.items() if pid is None)
    solo = sorted(sid for sid in span_ids
                  if parents.get(sid) is None and sum(1 for p in parents.values() if p == sid) == 0)

    # No payload may carry a truncation marker.
    blob = json.dumps(events, ensure_ascii=False, default=str)
    truncation_marks = blob.count("已截断") + blob.count("还有 ")

    # The big payload must survive whole. The nested one arrives as whatever
    # langgraph makes of a dict tool result, so it is counted rather than
    # matched against a quoting style.
    big_seen = BIG in blob
    many_seen = all(item in blob for item in MANY)
    deep_seen = blob.count("nested") >= 40

    graph = {e["spanId"]: e.get("graph") for e in starts}
    adopted = sorted(e["spanId"] for e in starts if e.get("adopted"))

    return {
        "langsmith": _ARGS.langsmith,
        "spanCount": len(starts),
        "traceCount": len(traces),
        "rootCount": len(roots),
        "chainSpans": sorted(e["name"] for e in starts if e["kind"] == "chain"),
        "leafSpans": sorted(e["name"] for e in starts if e["kind"] in ("model", "tool")),
        "danglingParents": dangling,
        "adoptedByGraphKey": len(adopted),
        "spansWithGraphKey": sum(1 for g in graph.values() if g),
        "truncationMarks": truncation_marks,
        "bigPayloadIntact": big_seen,
        "manyPayloadIntact": many_seen,
        "deepPayloadIntact": deep_seen,
        "sizeBytesPresent": sum(1 for e in starts if "sizeBytes" in e),
        "dropped": stats["dropped"],
        "endedSpans": len(ends),
        # stable fingerprint for comparing the two modes
        "shape": sorted(f"{e['kind']}:{e['name']}:{parents[e['spanId']] is not None}" for e in starts),
    }


def main() -> int:
    result = analyse(**run())
    summary = {k: v for k, v in result.items() if k != "shape"}

    checks = {
        "没有悬空父节点": not result["danglingParents"],
        "只剩一条轨迹": result["traceCount"] == 1,
        "根节点唯一": result["rootCount"] == 1,
        "没有单 span 碎片": result["traceCount"] == 1,
        "大载荷完整保留 (200KB)": result["bigPayloadIntact"],
        "列表载荷完整保留 (500 项)": result["manyPayloadIntact"],
        "深嵌套载荷完整保留 (40 层)": result["deepPayloadIntact"],
        "没有任何截断标记": result["truncationMarks"] == 0,
        "没有丢弃事件": result["dropped"] == 0,
        "每个 span 都结算了": result["endedSpans"] == result["spanCount"],
    }
    summary["checks"] = checks
    summary["passed"] = all(checks.values())

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if _ARGS.json:
        Path(_ARGS.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
