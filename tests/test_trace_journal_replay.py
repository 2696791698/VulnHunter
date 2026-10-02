"""Trace replay must start on a complete UTF-8 JSONL record."""

import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest


SERVER_DIR = Path(__file__).resolve().parents[1] / "web" / "server"


@pytest.fixture(scope="module")
def bridge(tmp_path_factory):
    root = tmp_path_factory.mktemp("trace-replay")
    spec = importlib.util.spec_from_file_location("trace_replay_bridge", SERVER_DIR / "main.py")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(os.environ, {
        "AGENT_TRACE_JOURNAL": str(root / "traces.jsonl"),
        "AUDIT_TASK_JOURNAL": str(root / "tasks.jsonl"),
        "EVAL_RUN_JOURNAL": str(root / "eval.jsonl"),
        "EVAL_AUTO_RESUME": "0",
    }):
        spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("cut_inside_multibyte", [True, False])
def test_replay_tail_begins_with_complete_record(tmp_path, bridge, monkeypatch, cut_inside_multibyte):
    lines = [
        (json.dumps({"sequence": 0, "payload": "中文"}, ensure_ascii=False) + "\n").encode(),
        b'{"sequence": 1}\n',
        b'{"sequence": 2}\n',
    ]
    data = b"".join(lines)
    cut = lines[0].index("中".encode()) + 1 if cut_inside_multibyte else len(lines[0])
    journal = tmp_path / "traces.jsonl"
    journal.write_bytes(data)

    seen = []
    monkeypatch.setattr(bridge, "REPLAY_MAX_BYTES", len(data) - cut)
    monkeypatch.setattr(bridge, "_apply_event", seen.append)
    bridge._replay_file(journal)

    assert [event["sequence"] for event in seen] == [1, 2]


def test_replay_skips_damaged_record(tmp_path, bridge, monkeypatch):
    journal = tmp_path / "traces.jsonl"
    journal.write_bytes(b'{"sequence": 1}\n\x94\n{"sequence": 2}\n')

    seen = []
    monkeypatch.setattr(bridge, "REPLAY_MAX_BYTES", 1024)
    monkeypatch.setattr(bridge, "_apply_event", seen.append)
    bridge._replay_file(journal)

    assert [event["sequence"] for event in seen] == [1, 2]
