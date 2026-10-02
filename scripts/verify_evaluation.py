"""Checks the benchmark-evaluation path: scope resolution, what a sample is
handed, how a verdict becomes a score, and the run lifecycle.

Run inside the devcontainer, with the project venv:

    /home/vscode/.venv/bin/python scripts/verify_evaluation.py

Everything it does is local. The dataset, the run journal and the checkout root
are redirected to a temp directory; the dataset's repository is a throwaway git
repository built in that temp directory, and the audit agent is replaced by a
stub that records what it was handed. It never starts a container, calls a
model, or touches the network.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

REPO = Path("/workspaces/VulnHunter")
if not REPO.exists():
    REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

tmp = Path(tempfile.mkdtemp(prefix="vh-verify-eval-"))
os.environ["EVAL_DATASET_ROOT"] = str(tmp / "benchmark")
os.environ["EVAL_RUN_JOURNAL"] = str(tmp / "eval_runs.jsonl")
os.environ["AUDIT_TASK_JOURNAL"] = str(tmp / "tasks.jsonl")
os.environ["AUDIT_ROOT"] = str(tmp / "audits")

# A repository with two commits: the first has the vulnerable function, the
# second the fix. `commit_hash` is the fix, so the vulnerable side checks out
# its parent — which is the thing under test.
src = tmp / "src-repo"
src.mkdir(parents=True)
subprocess.run(["git", "init", "-q", str(src)], check=True)
(src / "pkg").mkdir()
VUL = "def f(x):\n    return eval(x)\n"
SEC = "def f(x):\n    return x\n"
(src / "pkg" / "mod.py").write_text(VUL, encoding="utf-8")
subprocess.run(["git", "-C", str(src), "add", "-A"], check=True)
subprocess.run(
    ["git", "-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "vulnerable"],
    check=True,
)
(src / "pkg" / "mod.py").write_text(SEC, encoding="utf-8")
subprocess.run(["git", "-C", str(src), "add", "-A"], check=True)
subprocess.run(
    ["git", "-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fix"],
    check=True,
)
FIX = subprocess.run(
    ["git", "-C", str(src), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
).stdout.strip()

# The dataset, in the layout the registry expects.
dataset_dir = Path(os.environ["EVAL_DATASET_ROOT"]) / "drea"
dataset_dir.mkdir(parents=True)
ITEM = {
    "id": "abcd1234",
    "project_name": "verify",
    "repo_url": str(src),
    "commit_hash": FIX,
    "language": "python",
    "cve_ids": ["CVE-2026-0001"],
    "cwe_ids": ["CWE-95"],
    "vuln_data": {"file_path": "pkg/mod.py", "code_before": VUL, "code_after": SEC},
}
(dataset_dir / "repopairbench_100.jsonl").write_text(
    json.dumps(ITEM) + "\n", encoding="utf-8",
)
(dataset_dir / "repopairbench_100_manifest.json").write_text(
    json.dumps([{"item_id": "abcd1234", "commit_message": "stop using eval"}]), encoding="utf-8",
)

spec = importlib.util.spec_from_file_location("bridge_under_test", REPO / "web/server/main.py")
main = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = main
spec.loader.exec_module(main)

import audit_agent  # noqa: E402  (needs the repo on sys.path, done above)
import evaluation  # noqa: E402

# Record queued ids without feeding them to the worker threads that main.py
# starts at import time. Their timed get still behaves like an empty queue.
class Sink:
    def __init__(self):
        self.items = []

    def put(self, item):
        self.items.append(item)

    def get(self, timeout=0.5):
        time.sleep(timeout)
        raise queue.Empty

    def task_done(self):
        pass


main._task_queue = Sink()
main._job_cancel_events = defaultdict(threading.Event)

failures: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"[{'ok ' if ok else 'FAIL'}] {label}: {got!r}")
    if not ok:
        failures.append(f"{label}: got {got!r}, want {want!r}")


def reject(label: str, fn, want: str) -> None:
    """Runs something that should be refused and checks its message."""
    try:
        fn()
    except Exception as exc:  # HTTPException from a handler, ValueError from the module
        detail = getattr(exc, "detail", str(exc))
        ok = want in detail
        print(f"[{'ok ' if ok else 'FAIL'}] {label}: {detail!r}")
        if not ok:
            failures.append(f"{label}: expected {want!r} in {detail!r}")
        return
    print(f"[{'ok ' if ok else 'FAIL'}] {label}: accepted, expected a rejection")
    failures.append(f"{label}: accepted")


def call(handler, payload):
    return asyncio.run(handler(payload))


dataset = evaluation.datasets(refresh=True)["drea"]
check("dataset loaded", len(dataset.items), 1)
check("manifest joined in", dataset.items[0].commit_message, "stop using eval")

print()
print("=== a sample knows which side of the pair it is ===")
vul = evaluation.sample_input(dataset, "abcd1234", "vul")
sec = evaluation.sample_input(dataset, "abcd1234", "sec")
check("vulnerable side checks out the fix's parent", vul["ref"], f"{FIX}^")
check("vulnerable side gets the pre-fix code", vul["code"], VUL)
check("vulnerable side is labelled vulnerable", vul["truth"], "vulnerable")
check("patched side checks out the fix itself", sec["ref"], FIX)
check("patched side gets the post-fix code", sec["code"], SEC)
check("patched side is labelled non-vulnerable", sec["truth"], "non-vulnerable")

print()
print("=== scope resolution ===")
FULL = {"projects": [], "cweIds": [], "search": "", "types": "both"}


def scope(**overrides):
    return {**FULL, **overrides}


def samples(**overrides):
    return evaluation.resolve_samples(dataset, scope(**overrides))


check("both types -> two samples", len(samples()), 2)
check("vul only -> one sample", [s["type"] for s in samples(types="vul")], ["vul"])
check("pair members stay adjacent", [s["type"] for s in samples()], ["vul", "sec"])
check("a non-matching cwe resolves to no samples", len(samples(cweIds=["CWE-9999"])), 0)
check("a matching cwe resolves", len(samples(cweIds=["CWE-95"])), 2)
check("search matches the project name", len(samples(search="verify")), 2)
check("search matches the file path", len(samples(search="pkg/mod")), 2)
check("search matches the cve", len(samples(search="CVE-2026")), 2)
check("an explicit selection wins over the filters",
      len(samples(itemIds=["abcd1234"], projects=["nothing-matches"])), 2)
check("title counts items and samples",
      evaluation.scope_summary(dataset, scope())["title"],
      "全部 1 项 · 漏洞 + 修复版（2 个样例）")
# The preview runs on every edit, so a filter that matches nothing has to be an
# answer with a zero in it, not a rejection the page would show as an error.
empty_preview = evaluation.scope_summary(dataset, scope(cweIds=["CWE-9999"]))
check("an empty scope previews as zero rather than failing",
      (empty_preview["itemCount"], empty_preview["sampleCount"]), (0, 0))

reject("a non-matching cwe is refused when creating a run",
       lambda: evaluation.create_run(dataset, scope(cweIds=["CWE-9999"])), "没有可测评的样例")
reject("an unknown item is refused", lambda: evaluation.resolve_samples(dataset, scope(itemIds=["nope"])), "数据集里没有")
reject("an unknown type is refused", lambda: evaluation.resolve_samples(dataset, scope(types="maybe")), "样例类型")
reject("an unknown dataset is refused", lambda: main._require_dataset("nope"), "未找到数据集")

print()
print("=== the structured assessment contract ===")
check("zero is a valid non-vulnerable verdict",
      audit_agent.parse_audit_result('{"verdict":0,"reproduction_report":null}').verdict, 0)
check("one is a valid vulnerable verdict with a report",
      audit_agent.parse_audit_result(json.dumps({
          "verdict": 1,
          "reproduction_report": {
              "summary": "Unsafe evaluation",
              "affected_location": "pkg/mod.py:f",
              "preconditions": [],
              "steps": ["Submit attacker-controlled input."],
              "expected_effect": "The submitted expression is evaluated by the application.",
              "observed_effect": None,
              "poc": "eval(input)",
              "verification_status": "static_inferred",
              "evidence": [{"kind": "file", "ref": "pkg/mod.py", "quote": "return eval(x)"}],
          },
      })).verdict, 1)
reject("one without a report is invalid",
       lambda: audit_agent.parse_audit_result('{"verdict":1,"reproduction_report":null}'),
       "requires a reproduction report")
reject("zero with a report is invalid",
       lambda: audit_agent.parse_audit_result(json.dumps({
           "verdict": 0,
           "reproduction_report": {
               "summary": "Unexpected report", "affected_location": "pkg/mod.py",
               "steps": ["Step"], "expected_effect": "Effect", "observed_effect": None,
               "verification_status": "static_inferred",
               "evidence": [{"kind": "file", "ref": "pkg/mod.py"}],
           },
       })), "must not include a reproduction report")

print()
print("=== metrics ===")


def row(item, kind, prediction, status="done", truth=None):
    return {
        "id": f"{item}-{kind}", "runId": "r", "itemId": item, "type": kind,
        "truth": truth or ("vulnerable" if kind == "vul" else "non-vulnerable"),
        "status": status, "prediction": prediction,
    }


metrics = evaluation.compute_metrics([
    row("A", "vul", "vulnerable"), row("A", "sec", "non-vulnerable"),  # both right
    row("B", "vul", "vulnerable"), row("B", "sec", "vulnerable"),  # both flagged
    row("C", "vul", "non-vulnerable"), row("C", "sec", "vulnerable"),  # reversed
    row("D", "vul", None), row("D", "sec", None, status="failed"),  # no verdict
])
# D/sec never ran, so it is left out of the matrix; D/vul ran and did not comply,
# so it is a miss. That is the whole distinction.
check("confusion matrix", metrics["confusion"], {"tp": 2, "fp": 2, "tn": 1, "fn": 2})
check("a ran-but-unparseable answer is a miss, counted separately",
      (metrics["unparsed"], metrics["failed"]), (1, 1))
check("the matrix and what was left out add up",
      (metrics["counted"], metrics["excluded"], metrics["finished"]), (7, 1, 8))
check("recall", metrics["recall"]["value"], 0.5)
check("fpr", metrics["fpr"]["value"], 0.6667)
check("youden's j", metrics["youdenJ"]["value"], -0.1667)
check("pair decomposition", metrics["pairs"],
      {"total": 3, "correct": 1, "vulnerable": 1, "nonVulnerable": 0, "reversed": 1})
check("a pair with a missing verdict is not scored",
      metrics["pairs"]["total"] < 4, True)
check("an unfinished sample is left out",
      evaluation.compute_metrics([row("E", "vul", None, status="running")])["finished"], 0)
check("an empty run invents no numbers",
      evaluation.compute_metrics([])["recall"]["value"], None)

# The bug this counting rule exists to prevent: a run cancelled after nothing
# had finished must not report recall 0% / FPR 100%, which is a claim about the
# model that the run never tested.
cancelled_run = evaluation.compute_metrics([
    row("A", "vul", None, status="cancelled"),
    row("A", "sec", None, status="cancelled"),
])
check("a wholly cancelled run reports no metrics at all",
      (cancelled_run["counted"], cancelled_run["cancelled"],
       cancelled_run["confusion"], cancelled_run["recall"]["value"],
       cancelled_run["fpr"]["value"]),
      (0, 2, {"tp": 0, "fp": 0, "tn": 0, "fn": 0}, None, None))

print()
print("=== POST /api/eval/runs: payload -> queued samples ===")
main._task_queue.items.clear()
created = call(main.post_eval_run, {"datasetId": "drea", "scope": scope()})
check("accepted", created["status"], "queued")
check("queued one id per sample", len(main._task_queue.items), 2)
check("it queued the samples it reported", sorted(main._task_queue.items),
      sorted(sample["id"] for sample in evaluation.samples_of(created["id"])))
reject("a bad dataset is refused", lambda: call(main.post_eval_scope, {"datasetId": "nope"}), "未找到数据集")

# The wall clock alone is not a unique key: runs created back to back land in the
# same millisecond, and a collision would make one run overwrite another while
# both stayed listed.
back_to_back = [
    call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})["id"]
    for _ in range(5)
]
check("runs created back to back get distinct ids", len(set(back_to_back)), 5)
check("and each of them is listed exactly once",
      len(evaluation.runs()), len({run["id"] for run in evaluation.runs()}))

print()
print("=== _run_eval_sample: checkout -> what audit_agent.run() is handed ===")

captured: list = []


class FakeAuditModule:
    """Stands in for audit_agent so no container or model call happens.

    It answers with a structured verdict derived from the code it was handed,
    which is how the script tells which snapshot the checkout actually contained.
    """

    FunctionTarget = audit_agent.FunctionTarget
    parse_audit_result = staticmethod(audit_agent.parse_audit_result)
    prediction_label = staticmethod(audit_agent.prediction_label)
    PROJECT_ROOT = ""

    def run(self, target=None, **kwargs):
        captured.append({
            "target": target,
            "disk_code": (Path(kwargs["project_root"]) / target.file_path).read_text(encoding="utf-8"),
        })
        code = (target.code if target else "") or ""
        verdict = 1 if "eval(" in code else 0
        report = None
        if verdict == 1:
            report = {
                "summary": "Unsafe evaluation of attacker-controlled input.",
                "affected_location": f"{target.file_path}:f",
                "preconditions": [],
                "steps": ["Submit attacker-controlled input."],
                "expected_effect": "The submitted expression is evaluated by the application.",
                "observed_effect": None,
                "poc": "eval(input)",
                "verification_status": "static_inferred",
                "evidence": [{"kind": "file", "ref": target.file_path, "quote": "return eval(x)"}],
            }
        return json.dumps({"verdict": verdict, "reproduction_report": report})


main._audit_module = FakeAuditModule()

samples_of_run = evaluation.samples_of(created["id"])
main._run_eval_sample(samples_of_run[0]["id"])
main._run_eval_sample(samples_of_run[1]["id"])
evaluation.refresh_run_status(created["id"])

run = evaluation.public_run(evaluation.get_run(created["id"]))
# Through `public_sample`, which is what the page is served: the stored record
# carries the verdict, and the score is derived from it on the way out.
by_type = {
    sample["type"]: evaluation.public_sample(dataset, sample)
    for sample in evaluation.samples_of(created["id"])
}

check("both samples finished", run["status"], "done")
check("progress adds up", run["progress"]["finished"], 2)
check("the structured agent received both samples", len(captured), 2)
check("the vulnerable sample was handed the pre-fix code",
      "eval(" in captured[0]["target"].code, True)
check("the patched sample was handed the post-fix code",
      "eval(" in captured[1]["target"].code, False)
check("both were told where the function lives",
      [item["target"].file_path for item in captured], ["pkg/mod.py", "pkg/mod.py"])
check("the vulnerable sample scored as a hit",
      (by_type["vul"]["prediction"], by_type["vul"]["correct"]), ("vulnerable", True))
check("the patched sample scored as a hit",
      (by_type["sec"]["prediction"], by_type["sec"]["correct"]), ("non-vulnerable", True))
check("both members right -> the pair is correct",
      run["metrics"]["pairs"], {"total": 1, "correct": 1, "vulnerable": 0, "nonVulnerable": 0, "reversed": 0})
check("recall over the one vulnerable instance", run["metrics"]["recall"]["value"], 1.0)

print()
print("=== the checkout really contained the right snapshot ===")
# The stub answered from the code it was handed, but the point of the parent
# ref is what is *on disk*: read the file the agent would have read.
check("the vulnerable checkout still has the vulnerable function",
      "eval(" in captured[0]["disk_code"],
      True)
check("the patched checkout has the fix",
      "eval(" in captured[1]["disk_code"],
      False)
check("finished checkout is cleaned up",
      (Path(os.environ["AUDIT_ROOT"]) / samples_of_run[0]["id"]).exists(), False)

print()
print("=== an invalid structured result is stored as unparsed, not guessed ===")
unparsed_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})
unparsed_sample = evaluation.samples_of(unparsed_run["id"])[0]
main._audit_module = type("InvalidStructuredResult", (FakeAuditModule,), {
    "run": lambda self, target=None, **kwargs: "It looks exploitable to me.",
})()
main._run_eval_sample(unparsed_sample["id"])
evaluation.refresh_run_status(unparsed_run["id"])
stored = evaluation.get_sample(unparsed_sample["id"])
check("the answer is kept whole", stored["verdict"], "It looks exploitable to me.")
check("but no prediction is invented", stored["prediction"], None)
check("and it counts as a miss, not a hit",
      evaluation.public_run(evaluation.get_run(unparsed_run["id"]))["metrics"]["confusion"]["fn"], 1)

print()
print("=== a sample whose file is not in that commit fails, and says which ===")
missing_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})
missing_sample = evaluation.samples_of(missing_run["id"])[0]
# The dataset says where the function is; point it somewhere this commit does
# not have, which is the case the checkout cannot satisfy.
dataset.items[0].file_path = "pkg/gone.py"
main._run_eval_sample(missing_sample["id"])
evaluation.refresh_run_status(missing_run["id"])
check("the sample failed", evaluation.get_sample(missing_sample["id"])["status"], "failed")
check("the failure names the path",
      "找不到 pkg/gone.py" in (evaluation.get_sample(missing_sample["id"])["error"] or ""), True)
dataset.items[0].file_path = "pkg/mod.py"

print()
print("=== cancel, retry, and replay ===")
# The run created earlier already ran both of its samples, so cancelling it has
# nothing left to drop and retrying it has nothing to re-queue.
check("nothing queued left to cancel", evaluation.cancel_run(created["id"]), 0)
check("nothing without a verdict to retry", evaluation.retry_samples(created["id"]), [])

retried = evaluation.retry_samples(unparsed_run["id"])
check("an unparsed sample is retried", retried, [unparsed_sample["id"]])
check("retrying puts it back to queued",
      evaluation.get_sample(unparsed_sample["id"])["status"], "queued")
check("and the run follows it back",
      evaluation.refresh_run_status(unparsed_run["id"])["status"], "queued")

queued_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
check("cancelling drops exactly the queued samples",
      evaluation.cancel_run(queued_run["id"]), 2)
check("a cancelled sample is not marked as a failure",
      {sample["status"] for sample in evaluation.samples_of(queued_run["id"])}, {"cancelled"})
check("and it is not retried, having been stopped on purpose",
      evaluation.retry_samples(queued_run["id"]), [])
evaluation.refresh_run_status(queued_run["id"])
check("a run with nothing in flight reads as done",
      evaluation.public_run(evaluation.get_run(queued_run["id"]))["status"], "done")
check("and reports no metrics rather than a wall of misses",
      evaluation.public_run(evaluation.get_run(queued_run["id"]))["metrics"]["recall"]["value"],
      None)

# Cancelling marks the records; it cannot take them back off the queue. The
# worker therefore has to check the record when a cancelled id reaches it, or a
# cancelled run keeps going to completion behind the reader's back.
print()
print("=== a cancelled sample is skipped when its turn comes ===")
# An instance, not the class: `run` is a method, and `run(target)` on the class
# itself would bind `target` to `self` and answer 0 for every sample — a fake that
# agrees with nothing instead of with the code it is handed.
main._audit_module = FakeAuditModule()
stop_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
stop_ids = [sample["id"] for sample in evaluation.samples_of(stop_run["id"])]
evaluation.cancel_run(stop_run["id"])
audited_before = len(captured)
for sample_id in stop_ids:
    main._run_eval_sample(sample_id)
check("the worker audited none of them", len(captured) - audited_before, 0)
check("and left every one of them cancelled",
      {evaluation.get_sample(sample_id)["status"] for sample_id in stop_ids}, {"cancelled"})

retry_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})
retry_sample = evaluation.samples_of(retry_run["id"])[0]
main._run_eval_sample(retry_sample["id"])
# Back to the state a sample ends a failed run in: no verdict, nothing scored.
evaluation.update_sample(
    retry_sample["id"], status="failed", error="boom",
    prediction=None, verdict=None, endedAt=None,
)
check("a failed sample is retried", evaluation.retry_samples(retry_run["id"]), [retry_sample["id"]])
evaluation.refresh_run_status(retry_run["id"])
audited_before = len(captured)
main._run_eval_sample(retry_sample["id"])
check("a retried sample is audited when its turn comes", len(captured) - audited_before, 1)

print()
print("=== explicitly retrying a cancelled sample fills the original run ===")
cancelled_retry_run = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
cancelled_retry_samples = {s["type"]: s for s in evaluation.samples_of(cancelled_retry_run["id"])}
cancelled_id = cancelled_retry_samples["vul"]["id"]
completed_id = cancelled_retry_samples["sec"]["id"]
main._run_eval_sample(completed_id)
completed_before = dict(evaluation.get_sample(completed_id))
evaluation.update_sample(cancelled_id, status="cancelled", error="已停止", endedAt="before-retry")
evaluation.refresh_run_status(cancelled_retry_run["id"])
check("ordinary retry still leaves cancelled work alone",
      evaluation.retry_samples(cancelled_retry_run["id"]), [])
run_count_before = len(evaluation.runs())
main._task_queue.items.clear()
cancelled_retry_result = asyncio.run(main.post_eval_retry_cancelled(cancelled_retry_run["id"]))
check("explicit retry queues just the cancelled sample", main._task_queue.items, [cancelled_id])
check("explicit retry keeps the original run id", cancelled_retry_result["run"]["id"], cancelled_retry_run["id"])
check("explicit retry does not create another run", len(evaluation.runs()), run_count_before)
check("explicit retry keeps the original sample count", cancelled_retry_result["run"]["progress"]["total"], 2)
check("explicit retry clears the old run end time", cancelled_retry_result["run"]["endedAt"], None)
check("explicit retry preserves the completed counterpart", evaluation.get_sample(completed_id), completed_before)
check("cancelled sample becomes pending in the same metrics",
      (cancelled_retry_result["run"]["metrics"]["cancelled"], cancelled_retry_result["run"]["metrics"]["pending"]),
      (0, 1))
reject("a second click cannot queue the same sample again",
       lambda: asyncio.run(main.post_eval_retry_cancelled(cancelled_retry_run["id"])), "没有需要重跑的已取消样例")
check("a repeated request still queues it only once", main._task_queue.items, [cancelled_id])
main._run_eval_sample(cancelled_id)
filled_run = evaluation.public_run(evaluation.get_run(cancelled_retry_run["id"]))
check("the real worker puts the result into the original sample", evaluation.get_sample(cancelled_id)["status"], "done")
check("the original run now counts both sample results", filled_run["metrics"]["counted"], 2)
check("the original pair is complete again", filled_run["metrics"]["pairCorrectness"]["denominator"], 1)
check("the completed counterpart remains untouched", evaluation.get_sample(completed_id), completed_before)

runs_before = len(evaluation.runs())
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
check("every run is restored from the journal", len(evaluation.runs()), runs_before)
restored = evaluation.get_run(created["id"])
check("the restored run kept its samples",
      len(evaluation.samples_of(created["id"])), 2)
check("and its verdicts survived",
      {s["type"]: s["prediction"] for s in evaluation.samples_of(created["id"])},
      {"vul": "vulnerable", "sec": "non-vulnerable"})
check("the filled run keeps its original two sample ids after replay",
      {s["id"] for s in evaluation.samples_of(cancelled_retry_run["id"])}, {cancelled_id, completed_id})
check("the rerun result stays in the original metrics after replay",
      evaluation.public_run(evaluation.get_run(cancelled_retry_run["id"]))["metrics"]["counted"], 2)
check("an unfinished run restarts paused",
      evaluation.get_run(unparsed_run["id"])["status"], "paused")
check("its queued sample stays queued",
      evaluation.get_sample(unparsed_sample["id"])["status"], "queued")

print()
print("=== removing a run removes it for good ===")
doomed = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})["id"]
check("it is listed", any(run["id"] == doomed for run in evaluation.runs()), True)
check("removing it reports success", evaluation.drop_run(doomed), True)
check("it is gone from memory", evaluation.get_run(doomed), None)
check("its samples are gone too", evaluation.samples_of(doomed), [])
check("removing it twice is refused", evaluation.drop_run(doomed), False)

# Without purging the journal the run would come back on the next restart, which
# is the trap the trace journal already had to fix for "clear".
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
check("and a restart does not bring it back", evaluation.get_run(doomed), None)
check("the other runs are still there", len(evaluation.runs()) > 0, True)

print()
print("=== pause, resume, and restart ===")
pause = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
pause_ids = [s["id"] for s in evaluation.samples_of(pause["id"])]
check("pause endpoint changes the status",
      asyncio.run(main.post_eval_pause(pause["id"]))["run"]["status"], "paused")
check("worker cannot claim a paused sample",
      evaluation.claim_sample(pause_ids[0], "now"), False)
audited_before = len(captured)
main._run_eval_sample(pause_ids[0])
check("the queued job does not run while paused", len(captured), audited_before)
check("paused sample is still queued", evaluation.get_sample(pause_ids[0])["status"], "queued")
reject("a paused run cannot retry around the pause",
       lambda: asyncio.run(main.post_eval_retry(pause["id"])), "请先继续")
reject("a paused run cannot rerun cancelled work around the pause",
       lambda: asyncio.run(main.post_eval_retry_cancelled(pause["id"])), "请先继续")

main._task_queue.items.clear()
continued = asyncio.run(main.post_eval_resume(pause["id"]))
check("resume returns to queued", continued["run"]["status"], "queued")
check("resume queues each pending sample once", sorted(main._task_queue.items), sorted(pause_ids))
main._run_eval_sample(pause_ids[0])
check("a resumed sample runs", evaluation.get_sample(pause_ids[0])["status"], "done")

in_flight = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
in_flight_ids = [s["id"] for s in evaluation.samples_of(in_flight["id"])]
check("one sample may already be claimed before pause",
      evaluation.claim_sample(in_flight_ids[0], "now"), True)
asyncio.run(main.post_eval_pause(in_flight["id"]))
evaluation.update_sample(in_flight_ids[0], status="done", prediction="vulnerable", endedAt="later")
check("finishing an in-flight sample does not unpause the run",
      evaluation.refresh_run_status(in_flight["id"])["status"], "paused")
main._task_queue.items.clear()
check("resume only queues the untouched sample",
      asyncio.run(main.post_eval_resume(in_flight["id"]))["queued"], 1)
check("the finished sample is not queued again", main._task_queue.items, [in_flight_ids[1]])

# A sweep stopped by the machine going down: one sample has a verdict and one
# was in flight. Nothing in memory survives — only the journal does.
crash = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
crash_samples = {s["type"]: s["id"] for s in evaluation.samples_of(crash["id"])}
main._run_eval_sample(crash_samples["vul"])                      # finished
evaluation.update_sample(crash_samples["sec"], status="running")  # in flight
evaluation.refresh_run_status(crash["id"])

main._task_queue.items.clear()
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()

check("the verdict already earned survives the restart",
      evaluation.get_sample(crash_samples["vul"])["prediction"], "vulnerable")
check("the run reads as paused after restart",
      evaluation.get_run(crash["id"])["status"], "paused")
check("the pause is attributed to the restart",
      evaluation.public_run(evaluation.get_run(crash["id"]))["pausedReason"], "restart")
check("the sample that lost its turn is marked failed",
      evaluation.get_sample(crash_samples["sec"])["status"], "failed")
check("restart queues nothing by itself", main._task_queue.items, [])
check("worker cannot claim the interrupted run",
      evaluation.claim_sample(crash_samples["sec"], "now"), False)
resumed = asyncio.run(main.post_eval_resume(crash["id"]))
check("manual resume re-queues the interrupted sample",
      main._task_queue.items, [crash_samples["sec"]])
check("the finished sample is not re-queued",
      crash_samples["vul"] in main._task_queue.items, False)
check("the run follows its sample back to queued", resumed["run"]["status"], "queued")
check("the manual resume is recorded on the run",
      (resumed["run"]["resumedSamples"], bool(resumed["run"]["resumedAt"])), (1, True))
check("and the run stops claiming an end time",
      evaluation.get_run(crash["id"])["endedAt"], None)
reject("resume is not repeatable while active",
       lambda: asyncio.run(main.post_eval_resume(crash["id"])), "没有暂停")

# A deliberate stop is not the crash's to undo: the cancelled sample stays
# cancelled while its unfinished neighbour comes back.
mixed = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="both")})
mixed_samples = {s["type"]: s["id"] for s in evaluation.samples_of(mixed["id"])}
evaluation.update_sample(mixed_samples["vul"], status="running")
check("cancelling drops the waiting one only",
      evaluation.cancel_run(mixed["id"]), 1)
check("and leaves the one in flight alone",
      evaluation.get_sample(mixed_samples["vul"])["status"], "running")
evaluation.refresh_run_status(mixed["id"])

evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
main._task_queue.items.clear()
check("the mixed run restarts paused", evaluation.get_run(mixed["id"])["status"], "paused")
check("the mixed run does not auto-queue", main._task_queue.items, [])
check("only the unfinished sample of that run comes back on manual resume",
      asyncio.run(main.post_eval_resume(mixed["id"]))["queued"], 1)
check("its one queued id is the interrupted sample",
      main._task_queue.items, [mixed_samples["vul"]])
check("the cancelled one stays cancelled",
      evaluation.get_sample(mixed_samples["sec"])["status"], "cancelled")

# A pause deliberately made by the user must survive the same journal replay.
manual = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})
asyncio.run(main.post_eval_pause(manual["id"]))
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
check("manual pause survives a restart", evaluation.get_run(manual["id"])["status"], "paused")
check("manual pause keeps its reason", evaluation.get_run(manual["id"])["pausedReason"], "manual")

# A power cut can land between the sample and run journal records. The sample
# state wins: a stale `done` run with a queued sample must still need a click.
stale = call(main.post_eval_run, {"datasetId": "drea", "scope": scope(types="vul")})
evaluation.update_run(stale["id"], status="done")
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
check("a stale completed run with queued work restarts paused",
      evaluation.get_run(stale["id"])["status"], "paused")

print()
print("=== a torn last line does not take the next record with it ===")
# A power cut mid-write: the record reached the disk without its newline. The
# partial record is meant to be lost; the record appended *after* it is not.
with evaluation.EVAL_JOURNAL.open("a", encoding="utf-8") as handle:
    handle.write('{"kind": "sample", "id": "torn')
SURVIVOR = {
    "kind": "run", "id": "eval-after-a-torn-line", "status": "done",
    "createdAt": "2030-01-01T00:00:00+08:00",
}
evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
evaluation._journal([SURVIVOR])

evaluation._runs.clear()
evaluation._run_order.clear()
evaluation._samples.clear()
evaluation.replay_runs()
check("the record written after a torn one survives",
      evaluation.get_run(SURVIVOR["id"]) is not None, True)

print()
print("SUMMARY:", "ALL OK" if not failures else failures)
sys.exit(1 if failures else 0)
