"""Exercise the Agent stop API and audit worker without git, Docker or a model.

Run with FastAPI and its test client dependency:
    uv run --no-project --with fastapi --with httpx python scripts/verify_agent_stop.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient


with tempfile.TemporaryDirectory() as temp_dir:
    root = Path(temp_dir)
    os.environ["AGENT_TRACE_JOURNAL"] = str(root / "traces.jsonl")
    os.environ["AUDIT_TASK_JOURNAL"] = str(root / "tasks.jsonl")
    os.environ["EVAL_RUN_JOURNAL"] = str(root / "eval.jsonl")
    os.environ["AUDIT_ROOT"] = str(root / "audits")
    os.environ["EVAL_AUTO_RESUME"] = "0"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web" / "server"))

    import main

    task_id = "audit-stop-check"
    trace_id = "trace-stop-check"
    entered = threading.Event()
    cancel_event = threading.Event()
    main._job_cancel_events[task_id] = cancel_event
    main._tasks[task_id] = {
        "id": task_id,
        "url": "https://example.test/repo.git",
        "commit": "main",
        "mode": "project",
        "status": "queued",
        "createdAt": main._now_iso(),
        "endedAt": None,
    }

    def fake_run(*args, **kwargs):
        entered.set()
        assert kwargs["job_id"] == task_id
        assert kwargs["cancel_event"].wait(3), "stop signal was not delivered"
        raise asyncio.CancelledError()

    main._clone = lambda *args: None
    main._load_audit_module = lambda: SimpleNamespace(run=fake_run)
    worker = threading.Thread(target=main._run_task, args=(task_id,))
    worker.start()
    assert entered.wait(3), "audit worker did not start"

    main._apply_event({
        "type": "span.start",
        "traceId": trace_id,
        "spanId": trace_id,
        "parentId": None,
        "name": "audit",
        "kind": "chain",
        "startedAt": main._now_iso(),
        "tags": [f"bridge-job:{task_id}"],
    })
    with TestClient(main.app) as client:
        summary = client.get(f"/api/agent/traces/{trace_id}").json()
        assert summary["canStop"] is True
        response = client.post(f"/api/agent/traces/{trace_id}/stop")
        assert response.status_code == 200, response.text
        assert response.json()["stopRequested"] is True

        worker.join(timeout=5)
        assert not worker.is_alive(), "audit worker did not stop"
        assert main._tasks[task_id]["status"] == "cancelled"
        main._job_cancel_events.pop(task_id)
        summary = client.get(f"/api/agent/traces/{trace_id}").json()
        assert summary["status"] == "cancelled"
        assert summary["canStop"] is False
        assert client.post(f"/api/agent/traces/{trace_id}/stop").status_code == 409

        main._apply_event({
            "type": "span.start",
            "traceId": "external-trace",
            "spanId": "external-trace",
            "parentId": None,
            "name": "external",
            "kind": "chain",
            "startedAt": main._now_iso(),
        })
        assert client.post("/api/agent/traces/external-trace/stop").status_code == 409

        sample_id = "sample-stop-check"
        sample_trace = "trace-sample-check"
        sample = {
            "id": sample_id,
            "runId": "run-stop-check",
            "itemId": "item-stop-check",
            "type": "vul",
            "status": "queued",
            "endedAt": None,
        }
        sample_entered = threading.Event()
        sample_cancel = threading.Event()
        main._job_cancel_events[sample_id] = sample_cancel

        def claim_sample(_id, started_at):
            sample.update(status="cloning", startedAt=started_at)
            return True

        def clone_sample(_url, _ref, checkout):
            checkout.mkdir(parents=True)
            (checkout / "module.py").write_text("def test(): pass", encoding="utf-8")

        def fake_eval_run(*args, **kwargs):
            sample_entered.set()
            assert kwargs["job_id"] == sample_id
            assert kwargs["cancel_event"].wait(3), "sample stop signal was not delivered"
            raise asyncio.CancelledError()

        main.evaluation.get_sample = lambda _id: sample if _id == sample_id else None
        main.evaluation.claim_sample = claim_sample
        main.evaluation.get_run = lambda _id: {"datasetId": "test"}
        main.evaluation.datasets = lambda: {"test": object()}
        main.evaluation.sample_input = lambda *_args: {
            "url": "https://example.test/repo.git",
            "ref": "main",
            "filePath": "module.py",
            "code": "def test(): pass",
        }
        main.evaluation.update_sample = lambda _id, **changes: sample.update(changes)
        main.evaluation.refresh_run_status = lambda _id: None
        main._clone = clone_sample
        main._load_audit_module = lambda: SimpleNamespace(
            FunctionTarget=lambda **kwargs: kwargs,
            run=fake_eval_run,
        )
        sample_worker = threading.Thread(target=main._run_eval_sample, args=(sample_id,))
        sample_worker.start()
        assert sample_entered.wait(3), "evaluation worker did not start"
        main._apply_event({
            "type": "span.start",
            "traceId": sample_trace,
            "spanId": sample_trace,
            "parentId": None,
            "name": "evaluation",
            "kind": "chain",
            "startedAt": main._now_iso(),
            "tags": [f"bridge-job:{sample_id}"],
        })
        assert client.get(f"/api/agent/traces/{sample_trace}").json()["canStop"] is True
        assert client.post(f"/api/agent/traces/{sample_trace}/stop").status_code == 200
        sample_worker.join(timeout=5)
        assert not sample_worker.is_alive(), "evaluation worker did not stop"
        assert sample["status"] == "cancelled"
        main._job_cancel_events.pop(sample_id)
        assert client.get(f"/api/agent/traces/{sample_trace}").json()["status"] == "cancelled"

print("Agent stop API, audit cancellation and evaluation cancellation: OK")
