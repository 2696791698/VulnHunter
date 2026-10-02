"""RepoPairBench evaluation: dataset, scope resolution, verdict scoring, metrics.

Everything here is bookkeeping — reading the dataset, turning a scope into a
list of samples, validating a machine-readable verdict from an agent's answer,
and turning finished samples into metrics. It clones nothing, runs no container
and calls no model; ``web/server/main.py`` owns execution and calls into this
module for the rest.

The metric definitions follow the DREA artifact (``code/process/eval/match.py``)
so numbers computed here are comparable with the published ones:

* recall / FPR / F1 over the individual instances;
* Pair-Correctness over the (vulnerable, patched) pairs, which requires *both*
  members of a pair to be classified correctly;
* Youden's J = recall − FPR.

A sample that produced no parseable verdict — the agent failed or returned an
invalid structured result — is counted as a miss rather than dropped from the
denominator. Dropping them would inflate recall on exactly the runs that went
worst, and the counts are reported separately so the difference is visible.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import threading
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Datasets live in the repository (they are small metadata files, not the
# repositories themselves), so a checkout of this project is enough to evaluate.
DATASET_ROOT = Path(os.getenv("EVAL_DATASET_ROOT") or (REPO_ROOT / "benchmark"))
EVAL_JOURNAL = Path(os.getenv("EVAL_RUN_JOURNAL") or (REPO_ROOT / "eval_runs.jsonl"))
# Same idea as the task journal: append a line per state change, rotate when the
# file outgrows the budget. Records are small — the function bodies stay in the
# dataset and are looked up by item id.
EVAL_JOURNAL_MAX_BYTES = int(os.getenv("EVAL_JOURNAL_MAX_MB", "64")) * 1024 * 1024
_JOURNAL_LOCK = threading.RLock()

MAX_RUNS = 40
# The function body is echoed into the task the agent is given, and the same
# bound as the manual function-audit path keeps the two consistent.
MAX_FUNCTION_CODE_CHARS = 20_000

SAMPLE_TYPES = ("vul", "sec")
TYPE_LABELS = {"vul": "漏洞版本", "sec": "修复版本"}
TYPE_SCOPE = {"vul": "仅漏洞版", "sec": "仅修复版", "both": "漏洞 + 修复版"}
VULNERABLE_LABEL = "vulnerable"
NON_VULNERABLE_LABEL = "non-vulnerable"
LEGACY_LABEL_ALIASES = {"benign": NON_VULNERABLE_LABEL}


def normalize_eval_label(value: str | None) -> str | None:
    """Normalize historical labels while returning the current vocabulary."""
    return LEGACY_LABEL_ALIASES.get(value, value)

# The three choices the scope selector offers, labels included — the page renders
# this verbatim rather than keeping its own copy of them.
TYPE_OPTIONS = [
    {"value": "vul", "label": TYPE_SCOPE["vul"], "detail": "检出修复 commit 的父提交，审的是修复前的函数。"},
    {"value": "sec", "label": TYPE_SCOPE["sec"], "detail": "检出修复 commit 本身，审的是修复后的函数。"},
    {"value": "both", "label": TYPE_SCOPE["both"], "detail": "同一项的两个版本都审，组成一对。"},
]

# A `vul` sample is the parent of the fixing commit; a `sec` sample is the fix
# itself. Both are read-only dataset fields, but they end up in a git argv, so
# they are validated like any other ref before they get there.
REF_PATTERN = re.compile(r"^[0-9A-Za-z._/-]{4,120}\^?$")


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# Run ids carry a counter as well as the clock. The clock alone is not enough:
# two runs created in the same millisecond — a retry followed by a fresh start,
# or two quick clicks — would take the same id, and the second would overwrite
# the first in `_runs` while both stayed in `_run_order`. The list would show one
# run twice and a restart would restore only one of them.
_run_sequence = itertools.count(1)


def _next_run_id() -> str:
    while True:
        candidate = f"eval-{int(datetime.now().timestamp() * 1000)}-{next(_run_sequence)}"
        if candidate not in _runs:
            return candidate


# --------------------------------------------------------------------------- #
# Dataset
# --------------------------------------------------------------------------- #


class DatasetItem:
    """One vulnerability–fix pair, as the dataset describes it."""

    __slots__ = (
        "id", "project_name", "repo_url", "commit_hash", "language",
        "cve_ids", "cwe_ids", "file_path", "code_before", "code_after",
        "commit_message",
    )

    def __init__(self, record: dict, manifest: dict) -> None:
        self.id = str(record["id"])
        self.project_name = str(record.get("project_name") or "")
        self.repo_url = str(record.get("repo_url") or "")
        self.commit_hash = str(record.get("commit_hash") or "")
        self.language = str(record.get("language") or "")
        self.cve_ids = [str(value) for value in record.get("cve_ids") or []]
        self.cwe_ids = [str(value) for value in record.get("cwe_ids") or []]

        vuln_data = record.get("vuln_data") or {}
        self.file_path = str(vuln_data.get("file_path") or manifest.get("file_path") or "")
        self.code_before = str(vuln_data.get("code_before") or "")
        self.code_after = str(vuln_data.get("code_after") or "")
        self.commit_message = str(manifest.get("commit_message") or "")

    def summary(self) -> dict:
        """The item without its two function bodies — what a listing needs."""
        return {
            "id": self.id,
            "projectName": self.project_name,
            "cveIds": list(self.cve_ids),
            "cweIds": list(self.cwe_ids),
            "filePath": self.file_path,
            "repoUrl": self.repo_url,
            "commit": self.commit_hash,
            "language": self.language,
            "commitMessage": self.commit_message,
            "vulnerableChars": len(self.code_before),
            "patchedChars": len(self.code_after),
        }


class Dataset:
    """A named benchmark: its items, in the order the file lists them."""

    def __init__(self, id: str, name: str, description: str, items: list[DatasetItem]) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.items = items
        self.by_id = {item.id: item for item in items}

    def descriptors(self) -> dict:
        """Facets the scope selector offers, counted here rather than in the UI."""
        projects: dict[str, int] = {}
        cwes: dict[str, int] = {}
        for item in self.items:
            projects[item.project_name] = projects.get(item.project_name, 0) + 1
            for cwe in item.cwe_ids:
                cwes[cwe] = cwes.get(cwe, 0) + 1

        return {
            "typeOptions": [dict(option) for option in TYPE_OPTIONS],
            "projects": [
                {"value": name, "count": count}
                for name, count in sorted(projects.items(), key=lambda pair: (-pair[1], pair[0]))
            ],
            "cweIds": [
                {"value": cwe, "count": count}
                for cwe, count in sorted(cwes.items(), key=lambda pair: (-pair[1], pair[0]))
            ],
        }


# Registry. Adding a dataset means dropping its JSONL (+ optional manifest) into
# `benchmark/<id>/` and naming it here.
DATASET_SPECS = (
    {
        "id": "drea",
        "name": "RepoPairBench 100",
        "description": (
            "DREA 论文的 100 组 Python 漏洞修复对: 每组给出修复 commit、"
            "漏洞版本函数与修复版本函数。漏洞版本检出修复 commit 的父提交, "
            "修复版本检出修复 commit 本身。"
        ),
        "jsonl": "drea/repopairbench_100.jsonl",
        "manifest": "drea/repopairbench_100_manifest.json",
    },
)

_datasets: dict[str, Dataset] = {}


def _read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict) and record.get("id"):
                records.append(record)
    return records


def load_dataset(spec: dict) -> Dataset:
    """Reads one dataset off disk. Raises when the file is not there."""
    jsonl = DATASET_ROOT / spec["jsonl"]
    if not jsonl.is_file():
        raise FileNotFoundError(f"未找到数据集文件 {jsonl}")

    manifest_path = DATASET_ROOT / spec["manifest"] if spec.get("manifest") else None
    manifest: dict[str, dict] = {}
    if manifest_path is not None and manifest_path.is_file():
        # The manifest is optional and only enriches the items (commit message).
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = raw if isinstance(raw, list) else raw.get("items") or []
        for entry in entries:
            key = entry.get("item_id") or entry.get("id")
            if key:
                manifest[str(key)] = entry

    items = [DatasetItem(record, manifest.get(str(record["id"]), {})) for record in _read_jsonl(jsonl)]
    return Dataset(spec["id"], spec["name"], spec["description"], items)


def datasets(refresh: bool = False) -> dict[str, Dataset]:
    """Every dataset this bridge can evaluate, read once and kept."""
    global _datasets
    if refresh or not _datasets:
        loaded: dict[str, Dataset] = {}
        for spec in DATASET_SPECS:
            try:
                loaded[spec["id"]] = load_dataset(spec)
            except (OSError, ValueError):
                # A dataset that cannot be read is simply not offered; the page
                # then says there is nothing to evaluate rather than half a list.
                continue
        _datasets = loaded
    return _datasets


def sample_input(dataset: Dataset, item_id: str, sample_type: str) -> dict:
    """What executing one sample needs: where to check out, what to audit.

    ``ref`` is the *parent* of the fixing commit for the vulnerable side, which
    is what makes the vulnerable function the one sitting in that snapshot.
    """
    item = dataset.by_id.get(item_id)
    if item is None:
        raise KeyError(f"数据集里没有 {item_id}")

    if sample_type == "vul":
        ref = f"{item.commit_hash}^"
        code = item.code_before
        truth = VULNERABLE_LABEL
    elif sample_type == "sec":
        ref = item.commit_hash
        code = item.code_after
        truth = NON_VULNERABLE_LABEL
    else:
        raise ValueError(f"未知的样例类型 {sample_type}")

    if not REF_PATTERN.match(ref):
        raise ValueError(f"{item_id} 的检出 ref 不合法: {ref}")
    if len(code) > MAX_FUNCTION_CODE_CHARS:
        raise ValueError(f"{item_id} 的函数代码超过 {MAX_FUNCTION_CODE_CHARS} 个字符")

    return {
        "url": item.repo_url,
        "ref": ref,
        "filePath": item.file_path,
        "code": code,
        "truth": truth,
        "projectName": item.project_name,
        "cveIds": list(item.cve_ids),
        "cweIds": list(item.cwe_ids),
    }


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def _matches(item: DatasetItem, scope: dict) -> bool:
    projects = {str(value) for value in scope.get("projects") or []}
    if projects and item.project_name not in projects:
        return False

    cwes = {str(value) for value in scope.get("cweIds") or []}
    if cwes and not (set(item.cwe_ids) & cwes):
        return False

    search = str(scope.get("search") or "").strip().lower()
    if search:
        haystack = " ".join(
            [item.id, item.project_name, item.file_path, item.repo_url,
             *item.cve_ids, *item.cwe_ids]
        ).lower()
        if search not in haystack:
            return False

    return True


def resolve_items(dataset: Dataset, scope: dict) -> list[DatasetItem]:
    """The items a scope covers, in dataset order.

    An explicit ``itemIds`` selection wins over the filters: it is what the
    page sends when the reader ticked rows by hand, and honouring the filters
    on top of it would silently drop rows the reader picked.
    """
    wanted = [str(value) for value in scope.get("itemIds") or []]
    if wanted:
        by_id = dataset.by_id
        missing = [item_id for item_id in wanted if item_id not in by_id]
        if missing:
            raise ValueError(f"数据集里没有这些样例: {', '.join(missing[:5])}")
        chosen = [by_id[item_id] for item_id in wanted]
    else:
        chosen = [item for item in dataset.items if _matches(item, scope)]

    return chosen


def resolve_samples(dataset: Dataset, scope: dict) -> list[dict]:
    """The (item, type) samples a scope covers.

    An empty result is returned rather than raised: the scope selector previews
    a scope on every edit, and "this filter matches nothing yet" is an answer,
    not a failure. Creating a run out of one *is* a failure, and that check lives
    in `create_run`.

    The two members of a pair stay adjacent so a run's progress reads as pairs
    rather than as two long sweeps.
    """
    types = str(scope.get("types") or "both")
    if types not in ("vul", "sec", "both"):
        raise ValueError("样例类型只能是 vul / sec / both")
    chosen_types = SAMPLE_TYPES if types == "both" else (types,)

    items = resolve_items(dataset, scope)
    samples = [
        {"itemId": item.id, "type": sample_type}
        for item in items
        for sample_type in chosen_types
    ]

    return samples


def describe_scope(scope: dict, item_count: int, sample_count: int, dataset_total: int) -> str:
    """A one-line Chinese summary of what a scope resolved to."""
    if scope.get("itemIds"):
        head = f"指定 {item_count} 项"
    elif any(scope.get(key) for key in ("projects", "cweIds", "search")):
        head = f"筛选出 {item_count} / {dataset_total} 项"
    else:
        head = f"全部 {item_count} 项"

    kinds = TYPE_SCOPE.get(str(scope.get("types") or "both"), TYPE_SCOPE["both"])
    return f"{head} · {kinds}（{sample_count} 个样例）"


def scope_summary(dataset: Dataset, scope: dict) -> dict:
    """Resolves a scope without starting anything — the page's live preview."""
    samples = resolve_samples(dataset, scope)

    per_project: dict[str, int] = {}
    for sample in samples:
        item = dataset.by_id[sample["itemId"]]
        per_project[item.project_name] = per_project.get(item.project_name, 0) + 1

    item_count = len({sample["itemId"] for sample in samples})
    return {
        "itemCount": item_count,
        "sampleCount": len(samples),
        "types": str(scope.get("types") or "both"),
        "title": describe_scope(scope, item_count, len(samples), len(dataset.items)),
        "projects": [
            {"value": name, "count": count}
            for name, count in sorted(per_project.items(), key=lambda pair: (-pair[1], pair[0]))
        ][:12],
    }


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

# Statuses a sample cannot move on from. `cancelled` is a terminal state of its
# own rather than a `failed` one: the metrics treat the two the same way (nothing
# was measured), but the page should not tell the reader that a run they stopped
# themselves "failed".
TERMINAL_STATUSES = ("done", "failed", "cancelled")
# Terminal statuses that produced nothing to score, and so stay out of the
# confusion matrix entirely.
UNRUN_STATUSES = ("failed", "cancelled")


def score_sample(prediction: str | None, truth: str) -> bool | None:
    """Whether a prediction matched the label, or None when there was none."""
    prediction = normalize_eval_label(prediction)
    truth = normalize_eval_label(truth)
    if prediction not in (VULNERABLE_LABEL, NON_VULNERABLE_LABEL):
        return None
    return prediction == truth


def _ratio(numerator: int, denominator: int) -> dict:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": round(numerator / denominator, 4) if denominator else None,
    }


def compute_metrics(samples: list[dict]) -> dict:
    """Detection metrics over the samples that actually produced a measurement.

    Three things can happen to a sample, and they are counted differently on
    purpose:

    * it answered with a verdict — scored, and in the confusion matrix;
    * it ran but the answer carried no parseable verdict — a **miss**: the agent
      did not comply with the output contract, which is a failure of the thing
      being measured;
    * it never ran — the clone failed, the service restarted, or the reader
      cancelled it. Counted as `failed` / `cancelled` and **kept out of the
      matrix**. Counting these as misses would report recall 0% and FPR 100% for
      a run cancelled after one sample, which is a claim about the model that the
      run never tested.

    `counted` is the size of the matrix (scored plus unparsed) and `excluded` is
    what was left out, so a reader can always tell how much of a run the numbers
    cover. Only terminal samples are considered, so a run in flight reports the
    metrics of the part it has finished rather than numbers that move underfoot.
    """
    tp = fp = tn = fn = 0
    unparsed = failed = cancelled = pending = 0
    # item id -> {sample type: prediction}, only for samples that produced one.
    # A pair is scored only when both of its members are in here, which is what
    # DREA does: a pair whose verdict failed to parse has nothing to compare.
    pairs: dict[str, dict[str, str]] = {}

    for sample in samples:
        status = sample.get("status")
        if status not in TERMINAL_STATUSES:
            pending += 1
            continue

        if status in UNRUN_STATUSES:
            if status == "cancelled":
                cancelled += 1
            else:
                failed += 1
            continue

        is_vul = sample.get("type") == "vul"
        prediction = normalize_eval_label(sample.get("prediction"))

        if prediction not in (VULNERABLE_LABEL, NON_VULNERABLE_LABEL):
            unparsed += 1
            if is_vul:
                fn += 1
            else:
                fp += 1
            continue

        correct = prediction == normalize_eval_label(sample.get("truth"))
        if is_vul:
            tp += 1 if correct else 0
            fn += 0 if correct else 1
        else:
            tn += 1 if correct else 0
            fp += 0 if correct else 1

        pairs.setdefault(sample["itemId"], {})[sample["type"]] = prediction

    complete = [pair for pair in pairs.values() if "vul" in pair and "sec" in pair]
    pair_total = len(complete)
    pair_correct = sum(
        1 for pair in complete
        if pair["vul"] == VULNERABLE_LABEL and pair["sec"] == NON_VULNERABLE_LABEL
    )
    # The auxiliary decomposition DREA reports: both members flagged vulnerable,
    # both flagged non-vulnerable, and the two labels swapped.
    pair_vulnerable = sum(
        1 for pair in complete
        if pair["vul"] == "vulnerable" and pair["sec"] == "vulnerable"
    )
    pair_non_vulnerable = sum(
        1 for pair in complete
        if pair["vul"] == NON_VULNERABLE_LABEL and pair["sec"] == NON_VULNERABLE_LABEL
    )
    pair_reversed = sum(
        1 for pair in complete
        if pair["vul"] == NON_VULNERABLE_LABEL and pair["sec"] == VULNERABLE_LABEL
    )

    counted = tp + fp + tn + fn
    recall = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)

    youden = None
    if recall["value"] is not None and fpr["value"] is not None:
        youden = round(recall["value"] - fpr["value"], 4)

    return {
        "total": len(samples),
        "finished": counted + failed + cancelled,
        "counted": counted,
        "excluded": failed + cancelled,
        "unparsed": unparsed,
        "failed": failed,
        "cancelled": cancelled,
        "pending": pending,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "pairs": {
            "total": pair_total,
            "correct": pair_correct,
            "vulnerable": pair_vulnerable,
            "nonVulnerable": pair_non_vulnerable,
            "reversed": pair_reversed,
        },
        # The ratios sit at the same level as the counts they are computed from:
        # a second "metrics" level inside the metrics block would be one too many.
        "recall": recall,
        "fpr": fpr,
        "precision": _ratio(tp, tp + fp),
        "f1": _ratio(2 * tp, 2 * tp + fp + fn),
        "accuracy": _ratio(tp + tn, counted),
        "pairCorrectness": _ratio(pair_correct, pair_total),
        "youdenJ": {"value": youden, "numerator": None, "denominator": None},
    }


# --------------------------------------------------------------------------- #
# Run store
# --------------------------------------------------------------------------- #

_runs: dict[str, dict] = {}
_run_order: list[str] = []
_samples: dict[str, dict] = {}
_STORE_LOCK = threading.RLock()


def _journal(records: list[dict]) -> None:
    """Appends records to the run journal, rotating it when it outgrows the cap.

    `flush` *and* `fsync`: this journal is what a resumed run is rebuilt from, so
    a record that reached the OS but not the disk is a verdict the machine can
    still lose. Not every filesystem accepts `fsync`, and a refusal is not an
    error — the flush above is then the most that mount can give us.
    """
    try:
        with _JOURNAL_LOCK:
            lines = [json.dumps(record, ensure_ascii=False, default=str) for record in records]
            incoming = sum(len(line) + 1 for line in lines)
            if EVAL_JOURNAL.exists() and EVAL_JOURNAL.stat().st_size + incoming > EVAL_JOURNAL_MAX_BYTES:
                EVAL_JOURNAL.replace(EVAL_JOURNAL.parent / f"{EVAL_JOURNAL.name}.1")

            with EVAL_JOURNAL.open("a", encoding="utf-8") as handle:
                for line in lines:
                    handle.write(line + chr(10))
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
    except OSError:
        # Persistence is best-effort; it must not break the endpoint.
        pass


def _heal_journal_tail() -> None:
    """Gives a line a power cut left half-written its own newline.

    Replay already drops a partial record — it does not parse. What replay
    cannot fix is the append that comes after it: with no newline in between,
    the next record lands on the same line as the rubbish, and one torn record
    takes a whole, valid one down with it.
    """
    try:
        if not EVAL_JOURNAL.is_file() or not EVAL_JOURNAL.stat().st_size:
            return
        with EVAL_JOURNAL.open("rb+") as handle:
            handle.seek(-1, os.SEEK_END)
            if handle.read(1) != b"\n":
                handle.write(b"\n")
                handle.flush()
    except OSError:
        pass


def replay_runs() -> None:
    """Restores the run list and its samples, once, at start-up."""
    _heal_journal_tail()

    for path in (EVAL_JOURNAL.parent / f"{EVAL_JOURNAL.name}.1", EVAL_JOURNAL):
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(record, dict) or not record.get("id"):
                        continue
                    if record.get("kind") == "sample":
                        record["truth"] = normalize_eval_label(record.get("truth"))
                        record["prediction"] = normalize_eval_label(record.get("prediction"))
                        _samples[record["id"]] = record
                    elif record.get("kind") == "run":
                        _runs[record["id"]] = record
        except OSError:
            continue

    _run_order[:] = sorted(_runs, key=lambda run_id: _runs[run_id].get("createdAt") or "")
    del _run_order[:-MAX_RUNS]

    # Capture the run ids before rewriting sample states. This also covers a
    # crash between journaling a sample transition and refreshing its run.
    unfinished_run_ids = {
        sample.get("runId") for sample in _samples.values()
        if sample.get("status") in ("queued", "cloning", "running")
    }
    # A sample left mid-flight by a killed process is not running any more.
    # Queued samples have never started, so keep them ready for a manual resume.
    for sample in _samples.values():
        if sample.get("status") in ("cloning", "running"):
            sample["status"] = "failed"
            sample["error"] = "服务重启，样例中断"
            sample["endedAt"] = sample.get("endedAt") or _now_iso()
            _journal([sample])

    for run in _runs.values():
        if run.get("status") == "paused":
            continue
        restart_failure = any(
            sample.get("runId") == run["id"] and sample.get("error") == "服务重启，样例中断"
            for sample in _samples.values()
        )
        if run.get("status") in ("queued", "running", "interrupted") or run["id"] in unfinished_run_ids:
            if run["id"] not in unfinished_run_ids and not restart_failure:
                run["status"] = "done"
                run["endedAt"] = run.get("endedAt") or _now_iso()
                _journal([run])
                continue
            run["status"] = "paused"
            run["pausedReason"] = "restart"
            run["pausedAt"] = _now_iso()
            run["endedAt"] = None
            _journal([run])


def runs() -> list[dict]:
    return [_runs[run_id] for run_id in reversed(_run_order) if run_id in _runs]


def get_run(run_id: str) -> dict | None:
    return _runs.get(run_id)


def get_sample(sample_id: str) -> dict | None:
    return _samples.get(sample_id)


def samples_of(run_id: str) -> list[dict]:
    return [sample for sample in _samples.values() if sample.get("runId") == run_id]


def _trim_run(run_id: str) -> None:
    """Forgets a run's samples when the run itself is evicted or deleted."""
    for sample_id in [key for key, item in _samples.items() if item.get("runId") == run_id]:
        del _samples[sample_id]


def _purge_journal_unlocked(run_id: str) -> None:
    """Rewrites the journal with one run's records left out.

    Dropping a run from memory alone would only hide it until the next restart,
    when the journal is replayed and it comes back — the same trap the trace
    journal had to fix for "clear". The rotation file is rewritten too, since a
    long run can straddle the boundary between the two.

    A record without a `runId` is a run record, and is matched on its own id.
    """
    for path in (EVAL_JOURNAL.parent / f"{EVAL_JOURNAL.name}.1", EVAL_JOURNAL):
        if not path.is_file():
            continue

        try:
            kept: list[str] = []
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(record, dict):
                        continue
                    if record.get("runId") == run_id or (
                        record.get("kind") == "run" and record.get("id") == run_id
                    ):
                        continue
                    kept.append(line)

            with path.open("w", encoding="utf-8") as handle:
                for line in kept:
                    handle.write(line + chr(10))
                handle.flush()
        except OSError:
            # Best-effort, like the write path: a failed rewrite must not break
            # the endpoint, it just means the run reappears after a restart.
            continue


def _purge_journal(run_id: str) -> None:
    with _JOURNAL_LOCK:
        _purge_journal_unlocked(run_id)


def drop_run(run_id: str) -> bool:
    """Forgets a run, its samples, and their journal records."""
    with _STORE_LOCK:
        run = _runs.pop(run_id, None)
        if run is None:
            return False
        _run_order[:] = [item for item in _run_order if item != run_id]
        _trim_run(run_id)
        _purge_journal(run_id)
        return True


def create_run(dataset: Dataset, scope: dict) -> tuple[dict, list[dict]]:
    """Builds a run and its samples. Nothing is executed here."""
    plan = resolve_samples(dataset, scope)
    if not plan:
        raise ValueError("这个范围里没有可测评的样例")

    started = _now_iso()
    run_id = _next_run_id()

    item_count = len({sample["itemId"] for sample in plan})
    samples: list[dict] = []
    for index, sample in enumerate(plan):
        samples.append({
            "kind": "sample",
            "id": f"{run_id}-{index:04d}",
            "runId": run_id,
            "itemId": sample["itemId"],
            "type": sample["type"],
            "truth": VULNERABLE_LABEL if sample["type"] == "vul" else NON_VULNERABLE_LABEL,
            "status": "queued",
            "prediction": None,
            "verdict": None,
            "error": None,
            "checkout": None,
            "startedAt": None,
            "endedAt": None,
        })

    run = {
        "kind": "run",
        "id": run_id,
        "datasetId": dataset.id,
        "datasetName": dataset.name,
        "scope": _normalise_scope(scope),
        "types": str(scope.get("types") or "both"),
        "title": describe_scope(scope, item_count, len(samples), len(dataset.items)),
        "status": "queued",
        "pausedAt": None,
        "pausedReason": None,
        "createdAt": started,
        "startedAt": None,
        "endedAt": None,
        "sampleCount": len(samples),
        "error": None,
    }

    _runs[run_id] = run
    _run_order.append(run_id)
    del _run_order[:-MAX_RUNS]
    for sample in samples:
        _samples[sample["id"]] = sample

    _journal([run, *samples])
    return run, samples


def _normalise_scope(scope: dict) -> dict:
    """The scope as stored: only the fields that were actually used."""
    normalised = {
        "itemIds": [str(value) for value in scope.get("itemIds") or []],
        "projects": [str(value) for value in scope.get("projects") or []],
        "cweIds": [str(value) for value in scope.get("cweIds") or []],
        "search": str(scope.get("search") or ""),
        "types": str(scope.get("types") or "both"),
    }
    return normalised


def update_run(run_id: str, **changes) -> dict | None:
    with _STORE_LOCK:
        run = _runs.get(run_id)
        if run is None:
            return None
        run.update(changes)
        _journal([run])
        return run


def update_sample(sample_id: str, **changes) -> dict | None:
    with _STORE_LOCK:
        sample = _samples.get(sample_id)
        if sample is None:
            return None
        sample.update(changes)
        _journal([sample])
        return sample


def claim_sample(sample_id: str, started_at: str) -> bool:
    """Atomically gives one worker the right to start a queued sample."""
    with _STORE_LOCK:
        sample = _samples.get(sample_id)
        if sample is None or sample.get("status") != "queued":
            return False
        run = _runs.get(sample["runId"])
        if run is None or run.get("status") not in ("queued", "running"):
            return False
        sample.update(status="cloning", startedAt=started_at)
        _journal([sample])
        return True


def retry_samples(run_id: str, *, cancelled_only: bool = False) -> list[str]:
    """Retry unresolved work, or explicitly cancelled work, in the same run.

    Ordinary retry leaves cancelled samples alone. A separate user action opts
    into retrying only cancelled samples. Selection and reset share the store
    lock so repeated requests cannot publish the same sample twice.
    """
    with _STORE_LOCK:
        statuses = ("cancelled",) if cancelled_only else ("done", "failed")
        retried = []
        for sample in samples_of(run_id):
            if sample.get("status") not in statuses or sample.get("prediction") is not None:
                continue
            update_sample(
                sample["id"],
                status="queued",
                prediction=None,
                verdict=None,
                error=None,
                checkout=None,
                startedAt=None,
                endedAt=None,
            )
            retried.append(sample["id"])
        if retried:
            update_run(run_id, endedAt=None)
        return retried


def pause_run(run_id: str) -> dict:
    """Stop new samples from starting; already claimed samples may finish."""
    with _STORE_LOCK:
        run = _runs[run_id]
        if run.get("status") not in ("queued", "running") or not progress_of(run_id)["queued"]:
            raise ValueError("这次测评没有可暂停的待运行样例")
        return update_run(run_id, status="paused", pausedAt=_now_iso(), pausedReason="manual")


def resume_run(run_id: str) -> list[str]:
    """Return pending sample ids for the caller to queue after an explicit resume.

    Only a sample interrupted by a service restart is reset. Earlier failures,
    invalid verdicts and samples cancelled by the user keep their own outcomes.
    """
    with _STORE_LOCK:
        run = _runs[run_id]
        if run.get("status") != "paused":
            raise ValueError("这次测评没有暂停")
        pending = []
        for sample in samples_of(run_id):
            if sample.get("status") == "failed" and sample.get("error") == "服务重启，样例中断":
                update_sample(
                    sample["id"], status="queued", error=None, checkout=None,
                    startedAt=None, endedAt=None,
                )
            if sample.get("status") == "queued":
                pending.append(sample["id"])
        if not pending:
            raise ValueError("这次测评没有待继续的样例")
        update_run(
            run_id, status="queued", pausedAt=None, pausedReason=None,
            resumedAt=_now_iso(), resumedSamples=len(pending), endedAt=None,
        )
        return pending


def cancel_run(run_id: str) -> int:
    """Drops every sample of a run that is still waiting. The one in flight is
    left alone — the worker is already inside it and cancelling would mean
    killing the agent mid-audit."""
    with _STORE_LOCK:
        cancelled = 0
        for sample in samples_of(run_id):
            if sample.get("status") == "queued":
                update_sample(sample["id"], status="cancelled", error="已取消", endedAt=_now_iso())
                cancelled += 1
        return cancelled


def progress_of(run_id: str) -> dict:
    counts = {
        status: 0
        for status in ("queued", "cloning", "running", "done", "failed", "cancelled")
    }
    with _STORE_LOCK:
        for sample in samples_of(run_id):
            status = sample.get("status")
            if status in counts:
                counts[status] += 1
    counts["total"] = sum(counts.values())
    counts["finished"] = counts["done"] + counts["failed"] + counts["cancelled"]
    return counts


def refresh_run_status(run_id: str) -> dict | None:
    """Derives a run's status from the state of its samples.

    One function decides this rather than every transition writing its own, so a
    run cannot be left reading `done` after a sample was put back on the queue,
    or `running` after the last one finished. It only journals a real change.
    """
    with _STORE_LOCK:
        run = _runs.get(run_id)
        if run is None:
            return None

        counts = progress_of(run_id)
        if run.get("status") == "paused" and counts["queued"]:
            return run
        if counts["cloning"] or counts["running"]:
            if run.get("status") == "paused":
                return run
            status = "running"
            changes = {"startedAt": run.get("startedAt") or _now_iso()}
        elif counts["queued"]:
            status, changes = "queued", {}
        elif counts["total"]:
            status = "done"
            changes = {"endedAt": run.get("endedAt") or _now_iso()}
        else:
            return run
        changes = {key: value for key, value in changes.items() if not run.get(key)}

        if run.get("status") == status and not changes:
            return run
        return update_run(run_id, status=status, **changes)


def public_run(run: dict) -> dict:
    """A run as the page sees it: stored fields plus live progress and metrics."""
    samples = samples_of(run["id"])
    return {
        "id": run["id"],
        "datasetId": run.get("datasetId"),
        "datasetName": run.get("datasetName"),
        "title": run.get("title"),
        "types": run.get("types"),
        "scope": run.get("scope"),
        "status": run.get("status"),
        "createdAt": run.get("createdAt"),
        "startedAt": run.get("startedAt"),
        "endedAt": run.get("endedAt"),
        "pausedAt": run.get("pausedAt"),
        "pausedReason": run.get("pausedReason"),
        "resumedAt": run.get("resumedAt"),
        "resumedSamples": run.get("resumedSamples"),
        "error": run.get("error"),
        "sampleCount": run.get("sampleCount"),
        "progress": progress_of(run["id"]),
        "metrics": compute_metrics(samples),
    }


def public_sample(dataset: Dataset | None, sample: dict) -> dict:
    """A sample row with the dataset metadata joined in, so the page can render
    it without holding a copy of the dataset."""
    item = dataset.by_id.get(sample.get("itemId")) if dataset else None
    return {
        "id": sample["id"],
        "runId": sample.get("runId"),
        "itemId": sample.get("itemId"),
        "type": sample.get("type"),
        "status": sample.get("status"),
        "truth": normalize_eval_label(sample.get("truth")),
        "prediction": normalize_eval_label(sample.get("prediction")),
        "correct": score_sample(sample.get("prediction"), sample.get("truth")),
        "verdict": sample.get("verdict"),
        "error": sample.get("error"),
        "checkout": sample.get("checkout"),
        "startedAt": sample.get("startedAt"),
        "endedAt": sample.get("endedAt"),
        "projectName": item.project_name if item else None,
        "filePath": item.file_path if item else None,
        "cveIds": list(item.cve_ids) if item else [],
        "cweIds": list(item.cwe_ids) if item else [],
        "commit": item.commit_hash if item else None,
    }
