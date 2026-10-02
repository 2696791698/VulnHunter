"""Exercise a retry over a stale checkout containing root-owned container files.

Run inside the devcontainer with /home/vscode/.venv/bin/python. Only a temporary
repository and checkout under /tmp are touched; no model or audit is started.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import docker

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo))

with tempfile.TemporaryDirectory(prefix="vh-retry-cleanup-") as scratch:
    temp = Path(scratch)
    os.environ["AUDIT_ROOT"] = str(temp / "audits")
    os.environ["AUDIT_TASK_JOURNAL"] = str(temp / "tasks.jsonl")
    os.environ["EVAL_RUN_JOURNAL"] = str(temp / "eval_runs.jsonl")
    os.environ["EVAL_DATASET_ROOT"] = str(temp / "benchmark")

    spec = importlib.util.spec_from_file_location("retry_cleanup_bridge", repo / "web/server/main.py")
    main = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = main
    spec.loader.exec_module(main)

    source = temp / "source"
    source.mkdir()
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    (source / "test.txt").write_text("fresh checkout\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(source), "add", "test.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "-c", "user.name=Test", "-c", "user.email=test@example.com",
         "commit", "-qm", "fixture"],
        check=True,
    )
    commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()

    checkout = main.AUDIT_ROOT / "eval-retry-fixture"
    checkout.mkdir(parents=True)
    client = docker.from_env()
    try:
        client.containers.run(
            "mcr.microsoft.com/devcontainers/anaconda:3",
            ["sh", "-c", "mkdir -p /workspace/bot/__pycache__ && touch /workspace/bot/__pycache__/root.pyc"],
            volumes={str(checkout): {"bind": "/workspace", "mode": "rw"}},
            user="root",
            remove=True,
        )
    finally:
        client.close()

    assert (checkout / "bot/__pycache__/root.pyc").stat().st_uid == 0
    main._clone(str(source), commit, checkout)
    assert (checkout / "test.txt").read_text(encoding="utf-8") == "fresh checkout\n"
    assert not (checkout / "bot/__pycache__").exists()
    assert main._remove_checkout(checkout)
    assert not checkout.exists()
    print("[ok] retry replaced a root-owned stale checkout and removed the new checkout")
