"""A bounded in-memory trace cache must not bound the history shown by the API."""

import importlib.util
import json
import os
import threading
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


SERVER = Path(__file__).resolve().parents[1] / "web" / "server" / "main.py"


def _bridge(root: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, SERVER)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {
        "AGENT_TRACE_JOURNAL": str(root / "traces.jsonl"),
        "AUDIT_TASK_JOURNAL": str(root / "tasks.jsonl"),
        "EVAL_RUN_JOURNAL": str(root / "eval.jsonl"),
        "EVAL_AUTO_RESUME": "0",
    }):
        spec.loader.exec_module(module)
    module.MAX_TRACES = 2
    module.MAX_TRACE_BYTES = 128
    return module


def _events(trace_id: str):
    return [
        {
            "type": "span.start", "traceId": trace_id, "spanId": trace_id,
            "parentId": None, "name": trace_id, "kind": "chain",
            "startedAt": "2026-09-28T10:00:00+08:00", "inputs": {"text": "secret"},
            "sizeBytes": 100,
        },
        {
            "type": "span.end", "spanId": trace_id,
            "endedAt": "2026-09-28T10:00:01+08:00", "outputs": {"ok": True},
            "sizeBytes": 100,
        },
    ]


def test_history_survives_cache_eviction_and_restart(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_first")
    with TestClient(bridge.app) as client:
        for trace_id in ("trace-a", "trace-b", "trace-c"):
            assert client.post("/api/agent/events", json=_events(trace_id)).status_code == 200
        # The sender retries after a timeout even when the first POST committed.
        assert client.post("/api/agent/events", json=_events("trace-a")).json()["accepted"] == 0

        summaries = client.get("/api/agent/traces").json()["traces"]
        assert {item["id"] for item in summaries} == {"trace-a", "trace-b", "trace-c"}
        assert next(item for item in summaries if item["id"] == "trace-a")["sizeBytes"] == 200
        first = client.get("/api/agent/traces/trace-a").json()
        assert first["spans"][0]["inputs"] == {"text": "secret"}

    restarted = _bridge(tmp_path, "trace_history_second")
    with TestClient(restarted.app) as client:
        summaries = client.get("/api/agent/traces").json()["traces"]
        assert {item["id"] for item in summaries} == {"trace-a", "trace-b", "trace-c"}
        span = client.get("/api/agent/traces/trace-a/spans/trace-a").json()
        assert span["outputs"] == {"ok": True}


def test_legacy_snapshots_import_once_and_clear_removes_them(tmp_path):
    old = tmp_path / "traces.jsonl.saved-early.jsonl"
    newer = tmp_path / "traces.jsonl.1"
    old.write_text("".join(json.dumps(e) + "\n" for e in _events("old")), encoding="utf-8")
    newer.write_text(old.read_text(encoding="utf-8") + "".join(
        json.dumps(e) + "\n" for e in _events("new")
    ), encoding="utf-8")

    bridge = _bridge(tmp_path, "trace_history_migration")
    with TestClient(bridge.app) as client:
        assert {s["id"] for s in client.get("/api/agent/traces").json()["traces"]} == {"old", "new"}
        assert client.get("/api/agent/traces/old").json()["spanCount"] == 1
        assert client.delete("/api/agent/traces").status_code == 200
        assert client.get("/api/agent/traces").json()["traces"] == []

    restarted = _bridge(tmp_path, "trace_history_after_clear")
    with TestClient(restarted.app) as client:
        assert client.get("/api/agent/traces").json()["traces"] == []


def test_archived_payload_survives_single_trace_memory_trimming(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_payload")
    with TestClient(bridge.app) as client:
        assert client.post("/api/agent/events", json=_events("big")).status_code == 200
        assert client.get("/api/agent/traces/big/spans/big").json()["inputs"] == {"text": "secret"}
        assert client.get("/api/agent/traces/big").json()["spans"][0]["outputs"] == {"ok": True}


def test_archived_errors_and_stop_control_keep_their_meaning(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_status")
    bridge._tasks["audit-test"] = {"id": "audit-test", "status": "running", "endedAt": None}
    bridge._job_cancel_events["audit-test"] = threading.Event()
    events = [
        {"type": "span.start", "traceId": "trace-status", "spanId": "root", "parentId": None,
         "name": "root", "kind": "chain", "startedAt": "2026-09-28T10:00:00+08:00",
         "tags": ["bridge-job:audit-test"]},
        {"type": "span.start", "traceId": "trace-status", "spanId": "child", "parentId": "root",
         "name": "child", "kind": "tool", "startedAt": "2026-09-28T10:00:01+08:00"},
        {"type": "span.error", "spanId": "child", "endedAt": "2026-09-28T10:00:02+08:00", "error": "boom"},
        {"type": "span.error", "spanId": "root", "endedAt": "2026-09-28T10:00:03+08:00", "error": "boom"},
    ]
    with TestClient(bridge.app) as client:
        assert client.post("/api/agent/events", json=events).status_code == 200
        summary = client.get("/api/agent/traces").json()["traces"][0]
        assert summary["errorCount"] == 1
        assert summary["status"] == "running"
        assert summary["endedAt"] is None
        assert summary["canStop"] is True
        for filler in ("filler-one", "filler-two"):
            assert client.post("/api/agent/events", json=_events(filler)).status_code == 200
        assert "root" not in bridge._spans
        trace = client.get("/api/agent/traces/trace-status").json()
        assert trace["status"] == "running"
        assert trace["endedAt"] is None
        assert {s["id"]: s["propagated"] for s in trace["spans"]} == {"root": True, "child": False}
        assert client.post("/api/agent/traces/trace-status/stop").json()["stopRequested"] is True
        bridge._tasks["audit-test"].update(status="done", endedAt="2026-09-28T10:00:04+08:00")
        finished = client.get("/api/agent/traces/trace-status").json()
        assert finished["status"] == "error"
        assert finished["endedAt"] == "2026-09-28T10:00:04+08:00"


def test_trace_status_waits_for_job_completion_even_after_root_ends(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_success")
    bridge._tasks["audit-success"] = {"id": "audit-success", "status": "running", "endedAt": None}
    events = _events("trace-success")
    events[0]["tags"] = ["bridge-job:audit-success"]
    with TestClient(bridge.app) as client:
        assert client.post("/api/agent/events", json=events).status_code == 200
        summary = client.get("/api/agent/traces").json()["traces"][0]
        assert summary["status"] == "running"
        assert summary["endedAt"] is None
        assert bridge._summarise("trace-success")["status"] == "running"
        bridge._tasks["audit-success"].update(status="done", endedAt="2026-09-28T10:00:02+08:00")
        finished = client.get("/api/agent/traces/trace-success").json()
        assert finished["status"] == "ok"
        assert finished["endedAt"] == "2026-09-28T10:00:02+08:00"
        assert bridge._summarise("trace-success")["status"] == "ok"


def test_retry_does_not_make_an_old_trace_running_or_stoppable(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_retry")
    job_id = "eval-retry-0001"
    sample = {"id": job_id, "status": "running", "startedAt": "2026-09-28T01:59:00+00:00", "endedAt": None}
    bridge._job_cancel_events[job_id] = threading.Event()
    old_events = _events("old-attempt")
    old_events[0]["tags"] = [f"bridge-job:{job_id}"]
    old_events[1] = {
        "type": "span.error", "spanId": "old-attempt",
        "endedAt": "2026-09-28T10:00:01+08:00", "error": "old failure",
    }
    with patch.object(bridge.evaluation, "get_sample", side_effect=lambda sid: sample if sid == job_id else None):
        with TestClient(bridge.app) as client:
            assert client.post("/api/agent/events", json=old_events).status_code == 200
            assert client.get("/api/agent/traces/old-attempt").json()["status"] == "running"

            sample.update(status="queued", startedAt=None, endedAt=None)
            old = client.get("/api/agent/traces/old-attempt").json()
            assert old["status"] == "error"
            assert old["endedAt"] == "2026-09-28T10:00:01+08:00"
            assert old["canStop"] is False

            sample.update(status="running", startedAt="2026-09-28T02:30:00+00:00")
            new_events = _events("new-attempt")
            new_events[0]["tags"] = [f"bridge-job:{job_id}"]
            new_events[0]["startedAt"] = "2026-09-28T11:00:00+08:00"
            new_events[1]["endedAt"] = "2026-09-28T11:00:01+08:00"
            assert client.post("/api/agent/events", json=new_events).status_code == 200
            listed = {item["id"]: item for item in client.get("/api/agent/traces").json()["traces"]}
            assert listed["old-attempt"]["status"] == "error"
            assert listed["old-attempt"]["canStop"] is False
            assert listed["new-attempt"]["status"] == "running"
            assert listed["new-attempt"]["canStop"] is True
            assert client.post("/api/agent/traces/old-attempt/stop").status_code == 409
            assert bridge._job_cancel_events[job_id].is_set() is False


def test_interrupted_old_spans_stop_timing_without_changing_archive(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_interrupted")
    job_id = "eval-interrupted-0001"
    sample = {"id": job_id, "status": "queued", "startedAt": None, "endedAt": None}
    events = [
        {"type": "span.start", "traceId": "interrupted", "spanId": "root", "parentId": None,
         "name": "root", "kind": "chain", "startedAt": "2026-09-28T10:00:00+08:00",
         "tags": [f"bridge-job:{job_id}"]},
        {"type": "span.start", "traceId": "interrupted", "spanId": "child", "parentId": "root",
         "name": "child", "kind": "tool", "startedAt": "2026-09-28T10:00:01+08:00"},
        {"type": "span.end", "spanId": "child", "endedAt": "2026-09-28T10:00:03+08:00"},
    ]
    with patch.object(bridge.evaluation, "get_sample", side_effect=lambda sid: sample if sid == job_id else None):
        with TestClient(bridge.app) as client:
            assert client.post("/api/agent/events", json=events).status_code == 200
            assert bridge._archive.get_summary("interrupted")["status"] == "running"
            summary = client.get("/api/agent/traces").json()["traces"][0]
            assert summary["status"] == "interrupted"
            assert summary["endedAt"] == "2026-09-28T10:00:03+08:00"
            assert summary["canStop"] is False
            detail = client.get("/api/agent/traces/interrupted?payloads=false").json()
            root = next(item for item in detail["spans"] if item["id"] == "root")
            assert (root["status"], root["endedAt"]) == ("interrupted", summary["endedAt"])
            fetched = client.get("/api/agent/traces/interrupted/spans/root").json()
            assert (fetched["status"], fetched["endedAt"]) == ("interrupted", summary["endedAt"])
            assert bridge._archive.get_summary("interrupted")["status"] == "running"


def test_external_trace_stays_running_after_a_child_error(tmp_path):
    bridge = _bridge(tmp_path, "trace_history_external_error")
    events = [
        {"type": "span.start", "traceId": "external", "spanId": "root", "parentId": None,
         "name": "root", "kind": "chain", "startedAt": "2026-09-28T10:00:00+08:00"},
        {"type": "span.start", "traceId": "external", "spanId": "child", "parentId": "root",
         "name": "child", "kind": "tool", "startedAt": "2026-09-28T10:00:01+08:00"},
        {"type": "span.error", "spanId": "child", "endedAt": "2026-09-28T10:00:02+08:00",
         "error": "boom"},
    ]
    with TestClient(bridge.app) as client:
        assert client.post("/api/agent/events", json=events).status_code == 200
        summary = client.get("/api/agent/traces").json()["traces"][0]
        assert summary["errorCount"] == 1
        assert summary["status"] == "running"
        assert summary["endedAt"] is None
        assert client.post("/api/agent/events", json=[
            {"type": "span.end", "spanId": "root", "endedAt": "2026-09-28T10:00:03+08:00"},
        ]).status_code == 200
        assert client.get("/api/agent/traces/external").json()["status"] == "error"


def test_token_usage_history_survives_restart(tmp_path):
    bridge = _bridge(tmp_path, "trace_usage_first")
    events = [
        {"type": "span.start", "traceId": "trace-usage", "spanId": "model", "parentId": None,
         "name": "model", "kind": "model", "model": "test-model",
         "startedAt": "2026-09-28T10:00:00+08:00"},
        {"type": "span.end", "spanId": "model", "endedAt": "2026-09-28T10:00:01+08:00",
         "usage": {"inputTokens": 3, "outputTokens": 2, "totalTokens": 5}},
    ]
    with TestClient(bridge.app) as client:
        assert client.post("/api/agent/events", json=events).status_code == 200
        assert client.get("/api/agent/usage").json()["totals"]["totalTokens"] == 5

    restarted = _bridge(tmp_path, "trace_usage_second")
    with TestClient(restarted.app) as client:
        assert client.get("/api/agent/usage").json()["totals"]["totalTokens"] == 5
