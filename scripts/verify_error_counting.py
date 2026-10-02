"""Checks that a trace reports its failures, and not the spans they crossed.

One raising run reports its exception on every enclosing span, so a single
failure used to show up as `4 错误` in the monitoring page. The bridge now
points at the span the exception was raised in — the deepest one in a chain of
spans carrying the same error text — and counts those. Both halves matter: the
count says how many failures there were, and the span says where to look, which
is what the dashboard marks. This script pins down both: synthetic traces cover
the shapes (propagation, two independent failures, a retry, a caught child
followed by an unrelated parent failure, dangling parents), and the real journal
— when one is present — is replayed to check the invariant on actual runs.

The expected "which span" answers are written out by hand below, and the real
journal is checked against an independent longhand reading of the rule.

Run inside the devcontainer, with the project venv:

    /home/vscode/.venv/bin/python scripts/verify_error_counting.py

Prints a JSON summary on stdout; exit status is non-zero if any check failed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "web" / "server"))

_ARGS = argparse.ArgumentParser()
_ARGS.add_argument("--json", metavar="PATH", help="also write the result here")
_ARGS = _ARGS.parse_args()

import main  # noqa: E402  (needs the path setup above; replays the journal)

GATEWAY = (
    "OpenAIPermissionDeniedError: Error code: 403 - {'error': {'type': "
    "'server_error', 'message': 'Upstream response was not valid JSON'}}"
)
BAD_HASH = "RuntimeError: Invalid structured content returned by tool list_files"


def span_start(trace: str, span: str, parent: str | None, name: str, kind: str = "chain") -> dict:
    return {
        "type": "span.start",
        "traceId": trace,
        "spanId": span,
        "parentId": parent,
        "name": name,
        "kind": kind,
        "startedAt": "2026-01-01T00:00:00+00:00",
        "sizeBytes": 0,
    }


def span_end(span: str) -> dict:
    return {"type": "span.end", "spanId": span, "endedAt": "2026-01-01T00:00:01+00:00"}


def span_error(span: str, error: str) -> dict:
    return {"type": "span.error", "spanId": span, "endedAt": "2026-01-01T00:00:01+00:00", "error": error}


def cases() -> list[dict]:
    """The synthetic traces, each with the count it must report."""

    # A subagent's first model call dies; the exception is re-reported on the
    # three spans around it. This is the shape behind the reported "4 错误".
    propagation = [
        span_start("t-prop", "p-root", None, "LangGraph"),
        span_start("t-prop", "p-tools", "p-root", "tools"),
        span_start("t-prop", "p-task", "p-tools", "task", "tool"),
        span_start("t-prop", "p-exec", "p-task", "executor"),
        span_start("t-prop", "p-model", "p-exec", "model"),
        span_start("t-prop", "p-llm", "p-model", "ChatOpenAI", "model"),
        span_error("p-llm", GATEWAY),
        span_error("p-model", GATEWAY),
        span_error("p-exec", GATEWAY),
        span_error("p-task", GATEWAY),
        span_end("p-model"),
        span_end("p-exec"),
        span_end("p-tools"),
        span_end("p-root"),
    ]

    # Two subagents die for different reasons: two failures, and the spans that
    # contain them must swallow neither.
    independent = [
        span_start("t-two", "tw-root", None, "LangGraph"),
        span_start("t-two", "tw-a", "tw-root", "task", "tool"),
        span_start("t-two", "tw-b", "tw-root", "task", "tool"),
        span_start("t-two", "tw-llm-a", "tw-a", "ChatOpenAI", "model"),
        span_start("t-two", "tw-llm-b", "tw-b", "ChatOpenAI", "model"),
        span_error("tw-llm-a", GATEWAY),
        span_error("tw-llm-b", BAD_HASH),
        span_error("tw-a", GATEWAY),
        span_error("tw-b", BAD_HASH),
        span_end("tw-root"),
    ]

    # The same error twice in sequence is two failures — the run really did hit
    # the same wall twice — even though the text is identical.
    retry = [
        span_start("t-retry", "r-root", None, "LangGraph"),
        span_start("t-retry", "r-one", "r-root", "task", "tool"),
        span_start("t-retry", "r-two", "r-root", "task", "tool"),
        span_error("r-one", GATEWAY),
        span_error("r-two", GATEWAY),
        span_end("r-root"),
    ]

    # A tool fails, the agent carries on, then the span that contains it fails
    # for an unrelated reason: both are failures, neither hides the other.
    nested_distinct = [
        span_start("t-nested", "n-root", None, "LangGraph"),
        span_start("t-nested", "n-tools", "n-root", "tools"),
        span_start("t-nested", "n-task", "n-tools", "task", "tool"),
        span_start("t-nested", "n-llm", "n-task", "ChatOpenAI", "model"),
        span_error("n-llm", BAD_HASH),
        span_error("n-task", GATEWAY),
        span_end("n-root"),
    ]

    # A framework that re-wraps the message at each level defeats the text
    # comparison. Known boundary of the rule, asserted so a change is noticed.
    rewrapped = [
        span_start("t-rewrap", "w-root", None, "LangGraph"),
        span_start("t-rewrap", "w-task", "w-root", "task", "tool"),
        span_start("t-rewrap", "w-llm", "w-task", "ChatOpenAI", "model"),
        span_error("w-llm", "ValueError: boom"),
        span_error("w-task", "ToolException: ValueError: boom"),
        span_end("w-root"),
    ]

    clean = [
        span_start("t-clean", "c-root", None, "LangGraph"),
        span_start("t-clean", "c-task", "c-root", "task", "tool"),
        span_end("c-task"),
        span_end("c-root"),
    ]

    running = [
        span_start("t-running", "run-root", None, "LangGraph"),
        span_start("t-running", "run-llm", "run-root", "ChatOpenAI", "model"),
        span_end("run-root"),
    ]

    # The parent of the failing span was never reported: nothing proves this is
    # a repeat of a failure above it, so it has to stand on its own.
    dangling = [
        span_start("t-dangling", "d-llm", "d-missing", "ChatOpenAI", "model"),
        span_error("d-llm", GATEWAY),
    ]

    return [
        {"trace": "t-prop", "label": "传播: 1 个异常跨 4 层 → 1 个失败, 且指向最深处",
         "events": propagation, "errorCount": 1, "status": "error", "failures": ["p-llm"]},
        {"trace": "t-two", "label": "两个子 agent 各自失败 → 2",
         "events": independent, "errorCount": 2, "status": "error",
         "failures": ["tw-llm-a", "tw-llm-b"]},
        {"trace": "t-retry", "label": "同一个错误先后发生两次 → 2",
         "events": retry, "errorCount": 2, "status": "error",
         "failures": ["r-one", "r-two"]},
        {"trace": "t-nested", "label": "子级失败后父级另因失败 → 2",
         "events": nested_distinct, "errorCount": 2, "status": "error",
         "failures": ["n-llm", "n-task"]},
        {"trace": "t-rewrap", "label": "异常被逐层改写文案 → 分开计数 (规则边界)",
         "events": rewrapped, "errorCount": 2, "status": "error",
         "failures": ["w-llm", "w-task"]},
        {"trace": "t-clean", "label": "全部成功 → 0",
         "events": clean, "errorCount": 0, "status": "ok", "failures": []},
        {"trace": "t-running", "label": "还在运行且无错误 → 0",
         "events": running, "errorCount": 0, "status": "running", "failures": []},
        {"trace": "t-dangling", "label": "父 span 缺失 → 自己算一个",
         "events": dangling, "errorCount": 1, "status": "error", "failures": ["d-llm"]},
    ]


def measure(trace_id: str) -> dict:
    summary = main._summarise(trace_id)
    assert summary is not None, f"{trace_id} vanished from the store"
    return summary


def failures_of(trace_id: str) -> set[str]:
    """The spans the bridge points at as the failures themselves."""
    return {
        span["id"]
        for span in main._spans_with_error_origin(trace_id, payloads=False)
        if span["status"] == "error" and not span["propagated"]
    }


def expected_failures(spans: list[dict]) -> set[str]:
    """An independent reading of the same rule, to check the fast one against.

    The failure is the span the exception was raised in, so it is the one with
    no errored *descendant* carrying its text — everything above it is on the
    exception's way out. Written out longhand here on purpose: the bridge walks
    upwards once for speed, and a wrong direction is exactly the mistake that
    counting alone would not catch.
    """
    children: dict[str | None, list[dict]] = {}
    for span in spans:
        children.setdefault(span.get("parentId"), []).append(span)

    def has_errored_descendant(span: dict) -> bool:
        error = span.get("error") or ""
        stack = list(children.get(span["id"], []))
        while stack:
            child = stack.pop()
            if child["status"] == "error" and (child.get("error") or "") == error:
                return True
            stack.extend(children.get(child["id"], []))
        return False

    return {
        span["id"]
        for span in spans
        if span["status"] == "error" and not has_errored_descendant(span)
    }


def check_real_journal() -> dict:
    """Checks the invariant on whatever the replayed journal actually holds.

    Runs before the synthetic traces are fed in, so the two never mix.
    """
    traces = []
    checks = {}

    for trace_id in list(main._trace_order):
        spans = main._spans_of(trace_id)
        summary = main._summarise(trace_id)
        if summary is None:
            continue

        errored = [s for s in spans if s["status"] == "error"]
        texts = {s.get("error") or "" for s in errored}
        pointed_at = failures_of(trace_id)
        by_id = {span["id"]: span for span in spans}
        traces.append({
            "id": trace_id,
            "spans": summary["spanCount"],
            "erroredSpans": len(errored),
            "distinctTexts": len(texts),
            "errorCount": summary["errorCount"],
            "status": summary["status"],
            "failures": [
                f"{by_id[i]['kind']}:{by_id[i]['name']}" for i in sorted(pointed_at)
            ],
        })

        # A failure is never invented, and one exception is never counted more
        # than once per distinct text.
        checks[f"{trace_id[:8]} 计数介于 [不同文案数, 出错 span 数] 且与有无错误一致"] = (
            (summary["errorCount"] == 0) == (len(errored) == 0)
            and len(texts) <= summary["errorCount"] <= len(errored)
        )
        # ...and it points at the span the exception was raised in.
        checks[f"{trace_id[:8]} 失败落在异常抛出的那个 span 上"] = (
            pointed_at == expected_failures(spans)
        )

    # The reported case: several spans, one exception, and it must read as one.
    propagated = [t for t in traces if t["erroredSpans"] >= 3 and t["distinctTexts"] == 1]
    for t in propagated:
        checks[f"{t['id'][:8]}: {t['erroredSpans']} 个出错 span 同一文案 → 1 个失败"] = (
            t["errorCount"] == 1
        )

    return {"traces": traces, "propagatedCases": len(propagated), "checks": checks}


def run() -> int:
    real = check_real_journal()

    synthetic = {}
    checks = dict(real["checks"])
    for case in cases():
        for event in case["events"]:
            main._apply_event(event)
        summary = measure(case["trace"])
        synthetic[case["label"]] = {
            "errorCount": summary["errorCount"],
            "expected": case["errorCount"],
            "status": summary["status"],
            "failures": sorted(failures_of(case["trace"])),
            "expectedFailures": sorted(case["failures"]),
        }
        checks[f"合成: {case['label']}"] = (
            summary["errorCount"] == case["errorCount"] and summary["status"] == case["status"]
        )
        checks[f"合成: {case['label']} (指向的 span)"] = (
            failures_of(case["trace"]) == set(case["failures"])
        )

    result = {"real": real, "synthetic": synthetic, "checks": checks}
    result["passed"] = all(checks.values())

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if _ARGS.json:
        Path(_ARGS.json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(run())
