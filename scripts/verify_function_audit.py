"""Checks the function-level audit path: what the bridge accepts and refuses,
and that the target it is given reaches `audit_agent.run()` intact.

Run inside the devcontainer, with the project venv:

    /home/vscode/.venv/bin/python scripts/verify_function_audit.py

Everything it does is local: the task journal and checkout root are redirected
to a temp directory, the audit agent is replaced by a stub that records what it
was handed, and the clone source is a throwaway repository built in the temp
directory. It never starts a container, calls a model, or touches the network.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path("/workspaces/VulnHunter")
sys.path.insert(0, str(REPO))

tmp = Path(tempfile.mkdtemp(prefix="vh-verify-"))
os.environ["AUDIT_TASK_JOURNAL"] = str(tmp / "tasks.jsonl")
os.environ["AUDIT_ROOT"] = str(tmp / "audits")

spec = importlib.util.spec_from_file_location("bridge_under_test", REPO / "web/server/main.py")
main = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = main
spec.loader.exec_module(main)

# Swallow queued ids. The worker thread is already parked on the original queue
# object, so replacing the global here leaves it with nothing to clone.
main._task_queue = type("Sink", (), {"put": lambda self, item: None, "task_done": lambda self: None})()

import audit_agent  # noqa: E402  (needs the repo on sys.path, done above)

captured: list = []


class FakeAuditModule:
    """Stands in for audit_agent so no container or model call happens."""

    FunctionTarget = audit_agent.FunctionTarget

    def __init__(self):
        self.PROJECT_ROOT = ""

    def run(self, target=None):
        captured.append(target)
        # main.py assigns this on the real module; mirror it so the rendered
        # prompt shows the paths the agent would actually be given.
        audit_agent.PROJECT_ROOT = self.PROJECT_ROOT
        if target is not None:
            print("--- rendered function target ---")
            print(audit_agent.render_function_target(target))
            print("--- end ---")
        return "non-vulnerable"


main._audit_module = FakeAuditModule()

# A tiny local repository to clone from, so nothing goes over the network.
src = tmp / "src-repo"
subprocess.run(["git", "init", "-q", str(src)], check=True)
(src / "pkg").mkdir()
(src / "pkg" / "mod.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
subprocess.run(["git", "-C", str(src), "add", "-A"], check=True)
subprocess.run(
    ["git", "-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
    check=True,
)

failures: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'ok ' if ok else 'FAIL'}] {label}: {got!r}")
    if not ok:
        failures.append(f"{label}: got {got!r}, want {want!r}")


def submit(payload: dict):
    """Runs the real handler; returns the fields of the task it built, or the
    rejection detail."""
    try:
        task = asyncio.run(main.post_audit_task(payload))
    except Exception as exc:  # HTTPException from the handler
        return getattr(exc, "detail", f"{type(exc).__name__}: {exc}")
    return {key: task[key] for key in ("mode", "filePath", "functionCode")}


CODE = "def f(x):\n    return x\n"
# Only the blank lines around a snippet are dropped; that is what the bridge stores.
STORED_CODE = CODE.rstrip("\n")
WINDOWS_PATH = ".\\pkg\\mod.py"

print("=== POST /api/audit/tasks: payload -> task ===")
check("project mode", submit({"url": "https://x/y.git", "commit": "abc1234", "mode": "project"}),
      {"mode": "project", "filePath": None, "functionCode": None})
check("missing mode defaults to project", submit({"url": "https://x/y.git", "commit": "abc1234"}),
      {"mode": "project", "filePath": None, "functionCode": None})
check("function mode", submit({"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                               "filePath": "pkg/mod.py", "functionCode": CODE}),
      {"mode": "function", "filePath": "pkg/mod.py", "functionCode": STORED_CODE})
check("windows separators, ./ prefix, CRLF, blank lines around the snippet",
      submit({"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
              "filePath": WINDOWS_PATH, "functionCode": "  " + CODE + "\r\n\r\n"}),
      {"mode": "function", "filePath": "pkg/mod.py", "functionCode": "  " + STORED_CODE})

print()
print("=== rejections ===")
for label, payload, want in [
    ("unknown mode", {"url": "https://x/y.git", "commit": "abc1234", "mode": "whatever"}, "检测模式"),
    ("function without a path", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                                 "functionCode": CODE}, "文件路径不能为空"),
    ("function without code", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                               "filePath": "pkg/mod.py", "functionCode": "   "}, "函数代码不能为空"),
    ("absolute path", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                       "filePath": "/etc/passwd", "functionCode": CODE}, "不能是绝对路径"),
    ("windows drive", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                       "filePath": "C:/Windows/x.py", "functionCode": CODE}, "不能是绝对路径"),
    ("parent-relative path", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                              "filePath": "../../etc/passwd", "functionCode": CODE}, "路径段"),
    ("inner dot segment", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                           "filePath": "pkg/./mod.py", "functionCode": CODE}, "路径段"),
    ("shell metacharacters in the path", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                                          "filePath": "pkg/mod.py;rm -rf /", "functionCode": CODE}, "只能包含"),
    ("over-long code", {"url": "https://x/y.git", "commit": "abc1234", "mode": "function",
                        "filePath": "pkg/mod.py", "functionCode": "x" * 20001}, "最多 20000"),
]:
    detail = submit(payload)
    rejected = isinstance(detail, str) and want in detail
    print(f"[{'ok ' if rejected else 'FAIL'}] {label}: {detail!r}")
    if not rejected:
        failures.append(f"{label}: expected {want!r} in {detail!r}")

print()
print("=== _run_task: clone -> target handed to audit_agent.run() ===")


def run_task(label: str, mode: str, file_path: str | None) -> dict:
    captured.clear()
    task_id = f"verify-{len(main._tasks)}"
    main._tasks[task_id] = {
        "id": task_id, "url": str(src), "commit": "HEAD", "mode": mode,
        "filePath": file_path, "functionCode": CODE, "status": "queued",
        "createdAt": main._now_iso(), "startedAt": None, "endedAt": None,
        "checkout": None, "verdict": None, "error": None,
    }
    main._run_task(task_id)
    task = main._tasks[task_id]
    print(f"[{label}] status={task['status']} error={task['error']!r} verdict={task['verdict']!r}")
    return task


check("project task runs", run_task("project", "project", None)["status"], "done")
check("project task passes no target", captured, [None])

check("function task runs", run_task("function", "function", "pkg/mod.py")["status"], "done")
check("target carried the path", getattr(captured[0], "file_path", None), "pkg/mod.py")
# This path builds the task dict directly, so the code arrives exactly as it was
# put there — the blank-line trimming is the HTTP handler's doing, checked above.
check("target carried the code", getattr(captured[0], "code", None), CODE)

missing = run_task("missing file", "function", "pkg/nope.py")
check("a path that is not in the commit fails the task", missing["status"], "failed")
check("the failure names the path", "找不到 pkg/nope.py" in (missing["error"] or ""), True)

print()
print("=== replay of a task journalled before `mode` existed ===")
legacy = main._public_task({"id": "audit-old", "url": "https://x/y.git", "commit": "abc1234", "status": "done"})
check("legacy task reads as a project audit", legacy["mode"], "project")
check("legacy task has no function fields", (legacy["filePath"], legacy["functionCode"]), (None, None))

print()
print("SUMMARY:", "ALL OK" if not failures else failures)
sys.exit(1 if failures else 0)
