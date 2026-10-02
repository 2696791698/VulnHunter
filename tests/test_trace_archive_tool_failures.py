import hashlib
import json
import sys
from pathlib import Path


SERVER_DIR = Path(__file__).resolve().parents[1] / "web" / "server"
sys.path.insert(0, str(SERVER_DIR))

from trace_archive import TraceArchive  # noqa: E402


def test_explicit_tool_failure_is_counted_even_when_span_ended_normally(tmp_path):
    archive = TraceArchive(tmp_path / "archive")
    failed_output = {
        "type": "tool",
        "name": "list_calls",
        "content": [{"type": "text", "text": '{"success":false,"error":{"code":"QUERY_ERROR","message":"Joern tuple serialization failed"}}'}],
        "artifact": {"structured_content": {
            "success": False,
            "error": {"code": "QUERY_ERROR", "message": "Joern tuple serialization failed"},
        }},
        "tool_call_id": "call-failed",
    }
    events = [
        {"type": "span.start", "traceId": "trace-tool-failure", "spanId": "root",
         "parentId": None, "name": "audit", "kind": "chain",
         "startedAt": "2026-09-28T10:00:00+08:00"},
        {"type": "span.start", "traceId": "trace-tool-failure", "spanId": "tool",
         "parentId": "root", "name": "list_calls", "kind": "tool",
         "startedAt": "2026-09-28T10:00:01+08:00"},
        {"type": "span.end", "spanId": "tool", "endedAt": "2026-09-28T10:00:02+08:00",
         "outputs": failed_output},
        {"type": "span.end", "spanId": "root", "endedAt": "2026-09-28T10:00:03+08:00",
         "outputs": {"result": "continued"}},
    ]

    archive.append(events)
    summary = archive.get_summary("trace-tool-failure")
    spans = archive.read_trace("trace-tool-failure", payloads=True)

    assert summary["errorCount"] == 1
    tool_span = next(item for item in spans if item["id"] == "tool")
    assert tool_span["status"] == "error"
    assert "Joern tuple serialization failed" in tool_span["error"]


def test_tool_message_error_status_survives_trace_serialization():
    from langchain_core.messages import ToolMessage

    from agent_tracing import _jsonable

    message = ToolMessage(content="connection lost", tool_call_id="call-1", status="error")

    assert _jsonable(message)["status"] == "error"


def test_restart_rebuilds_legacy_trace_summaries_with_tool_failures(tmp_path):
    root = tmp_path / "archive"
    root.mkdir()
    trace_id = "legacy-tool-failure"
    events = [
        {"type": "span.start", "traceId": trace_id, "spanId": "root", "parentId": None,
         "name": "audit", "kind": "chain", "startedAt": "2026-09-28T10:00:00+08:00"},
        {"type": "span.start", "traceId": trace_id, "spanId": "tool", "parentId": "root",
         "name": "list_calls", "kind": "tool", "startedAt": "2026-09-28T10:00:01+08:00"},
        {"type": "span.end", "spanId": "tool", "endedAt": "2026-09-28T10:00:02+08:00",
         "outputs": {"type": "tool", "name": "list_calls", "content": [],
                      "artifact": {"structured_content": {"success": False, "error": "MappingException"}}}},
        {"type": "span.end", "spanId": "root", "endedAt": "2026-09-28T10:00:03+08:00",
         "outputs": {"result": "continued"}},
    ]
    trace_path = root / f"{hashlib.sha256(trace_id.encode('utf-8')).hexdigest()}.jsonl"
    trace_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    legacy_summary = {
        "id": trace_id,
        "name": "audit",
        "startedAt": "2026-09-28T10:00:00+08:00",
        "endedAt": "2026-09-28T10:00:03+08:00",
        "status": "ok",
        "spanCount": 2,
        "errorCount": 0,
        "usage": None,
        "revision": 4,
        "sizeBytes": trace_path.stat().st_size,
        "partial": False,
        "_jobId": None,
        "_archiveBytes": trace_path.stat().st_size,
    }
    (root / "index.jsonl").write_text(json.dumps(legacy_summary) + "\n", encoding="utf-8")

    restarted = TraceArchive(root)

    assert restarted.get_summary(trace_id)["errorCount"] == 1
    assert restarted.get_summary(trace_id)["status"] == "error"
