"""Optional bridge between the dashboard and ``check_environment.py``.

    python -m pip install -r web/server/requirements.txt
    python web/server/main.py                  # from the repository root

The Vite dev server proxies ``/api/*`` here (see ``web/vite.config.ts``). It is
the only source of the dashboard's content: with it stopped, the interface says
so rather than falling back to sample data.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_SCRIPT = REPO_ROOT / "check_environment.py"
ENV_FILE = REPO_ROOT / ".env"

# Every span event is appended here as it arrives, so a restart replays the
# journal instead of losing the run. Lives in the project directory (the only
# thing that survives a container rebuild) and is gitignored.
JOURNAL = Path(os.getenv("AGENT_TRACE_JOURNAL") or (REPO_ROOT / "agent_traces.jsonl"))
TASK_JOURNAL = Path(os.getenv("AUDIT_TASK_JOURNAL") or (REPO_ROOT / "audit_tasks.jsonl"))

# Checkouts live outside the project: `git clone` cannot write into the Windows
# bind mount (fsync fails there), and a checkout is reproducible from its url +
# commit anyway, so ephemeral storage costs nothing.
AUDIT_ROOT = Path(os.getenv("AUDIT_ROOT") or "/home/vscode/audits")
# A big repository takes a while: django's full history is ~250 MB and needs
# more than 15 minutes here. Raise this if your repositories are larger.
GIT_TIMEOUT_S = float(os.getenv("AUDIT_GIT_TIMEOUT_S", "1800"))
AUDIT_SCRIPT = REPO_ROOT / "audit_agent.py"

# Only network transports, and only refs that cannot be mistaken for a git flag.
URL_PATTERN = re.compile(r"^(https?://|git://|ssh://|git@)[^\s]+$")
REF_PATTERN = re.compile(r"^[0-9A-Za-z._/-]{4,120}$")
# Spans are stored whole, so retention is measured in bytes rather than in
# traces: a handful of audits is tens of megabytes each. This is the budget for
# everything held in memory, and it evicts oldest-trace-first.
JOURNAL_MAX_BYTES = int(os.getenv("AGENT_TRACE_JOURNAL_MAX_MB", "512")) * 1024 * 1024
MAX_TRACE_BYTES = int(os.getenv("AGENT_TRACE_MAX_MB", "384")) * 1024 * 1024
# At start-up only the tail of the journal is replayed, so a long-lived journal
# does not turn into an unbounded start-up cost.
REPLAY_MAX_BYTES = int(os.getenv("AGENT_TRACE_REPLAY_MB", "128")) * 1024 * 1024
# One small record per model span, kept outside the byte budget above: the
# token trend is a time series, and evicting traces must not erase its history.
MAX_USAGE_SAMPLES = 20_000

# Everything the dashboard shows about a check is defined here, in the backend,
# and sent over the wire — the frontend renders it verbatim and has no copy of
# its own. `target` reads the environment at request time (see `_refresh_env`),
# so editing `.env` is reflected without restarting this service.
#
# `target` returns None when the value it would report is not configured; the
# frontend renders that as "no data" rather than inventing a placeholder.
CHECKS = (
    {
        "id": "codebadger",
        "func": "check_codebadger",
        "name": "CodeBadger",
        "transport": "http",
        "transportLabel": "MCP · HTTP",
        "description": "以 HTTP 传输连接 CodeBadger MCP 服务，并拉取其工具列表。",
        "requires": ["CodeBadger_URL"],
        "icon": "bug",
        "target": lambda: os.getenv("CodeBadger_URL"),
    },
    {
        "id": "codeql",
        "func": "check_codeql",
        "name": "CodeQL",
        "transport": "stdio",
        "transportLabel": "MCP · stdio",
        "description": "以 stdio 子进程启动 CodeQL MCP 服务，验证其可被拉起并返回工具。",
        "requires": [],
        "icon": "database",
        "target": lambda: "codeql-development-mcp-server",
    },
    {
        "id": "semgrep",
        "func": "check_semgrep",
        "name": "Semgrep",
        "transport": "stdio",
        "transportLabel": "MCP · stdio",
        "description": "以 stdio 子进程启动 Semgrep MCP 服务，验证静态扫描能力可用。",
        "requires": [],
        "icon": "scan-search",
        "target": lambda: "semgrep mcp",
    },
    {
        "id": "docker-mcp",
        "func": "check_docker_mcp",
        "name": "docker-mcp",
        "transport": "sse",
        "transportLabel": "MCP · SSE",
        "description": "以 SSE 连接 docker-mcp 服务，验证容器化工具执行链路可用。",
        "requires": ["Docker_MCP_URL"],
        "icon": "container",
        "target": lambda: os.getenv("Docker_MCP_URL"),
    },
    {
        "id": "model",
        "func": "check_model",
        "name": "Model",
        "transport": "model",
        "transportLabel": "LLM · ChatOpenAI",
        "description": "用配置的模型创建 deep agent 并发起一次真实对话，验证模型连通性。",
        "requires": ["MODEL_NAME", "OPENAI_API_KEY", "OPENAI_BASE_URL"],
        "icon": "brain",
        "target": lambda: os.getenv("MODEL_NAME"),
    },
)


def _refresh_env() -> None:
    """Re-reads ``.env`` so edits show up without restarting the bridge.

    ``check_environment.py`` calls ``load_dotenv`` once at import time, which is
    why a stale value would otherwise stick for the lifetime of this process.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(ENV_FILE, override=True)


def _check_descriptor(spec: dict) -> dict:
    """The display half of a check — what it is, independent of any run."""
    return {
        "id": spec["id"],
        "name": spec["name"],
        "transport": spec["transport"],
        "transportLabel": spec["transportLabel"],
        "description": spec["description"],
        "requires": list(spec["requires"]),
        "icon": spec["icon"],
        "target": spec["target"](),
    }


class _TaskRoutingWriter(io.TextIOBase):
    """Keeps concurrent checks' ``print`` output apart.

    ``check_environment``'s helpers report failure by printing rather than by
    raising, so the only way to recover the error text is to capture stdout.
    asyncio is single-threaded, so attributing each write to the task that made
    it is enough to keep the five logs separate while they run concurrently.
    """

    def __init__(self) -> None:
        self._buffers: dict[object, list[str]] = {}

    def write(self, text: str) -> int:
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None
        self._buffers.setdefault(task, []).append(text)
        return len(text)

    def flush(self) -> None:
        pass

    def take(self, task: object) -> list[str]:
        joined = "".join(self._buffers.pop(task, []))
        return [line for line in joined.splitlines() if line.strip()]


_module = None


def _load_check_module():
    """Imports ``check_environment.py`` once, without running its ``__main__``."""
    global _module
    if _module is None:
        if not CHECK_SCRIPT.exists():
            raise RuntimeError(f"未找到 {CHECK_SCRIPT}")

        # `check_environment.py` lives in the repository root and imports its
        # siblings (`create_model`), so the root has to be importable — this
        # bridge is started from `web/server/`, which is not on the path.
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))

        spec = importlib.util.spec_from_file_location("vulnhunter_check_environment", CHECK_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _module = module
    return _module


def _extract_error(lines: list[str]) -> str:
    for line in reversed(lines):
        if line.startswith("❌"):
            _, _, detail = line.partition(": ")
            return detail or line
    return "检测未通过，详见原始输出。"


async def _run_one(module, spec: dict, writer: _TaskRoutingWriter) -> dict:
    task = asyncio.current_task()
    started = time.perf_counter()

    try:
        ok = bool(await getattr(module, spec["func"])())
    except Exception:
        # The helpers normally swallow their own errors; if one escapes, the
        # captured output still carries the reason.
        ok = False

    latency_ms = round((time.perf_counter() - started) * 1000)
    descriptor = _check_descriptor(spec)
    captured = writer.take(task)
    target = descriptor["target"]

    return {
        **descriptor,
        "state": "pass" if ok else "fail",
        "latencyMs": latency_ms,
        "message": None if ok else _extract_error(captured),
        "log": [
            f"$ check_environment · {spec['id']}",
            f"target={target if target is not None else '(未配置)'}",
            *captured,
        ],
    }


def _idle_results() -> list[dict]:
    """The checks this bridge can run, before any of them has been run."""
    return [
        {**_check_descriptor(spec), "state": "idle", "latencyMs": None, "message": None, "log": []}
        for spec in CHECKS
    ]


def _with_current_descriptors(results: list[dict]) -> list[dict]:
    """Overlays the current configuration onto a reading's measurements.

    The measured half (state, latency, message) belongs to that reading; the
    descriptive half (target, description, ...) should reflect `.env` as it is
    now, otherwise a config change would not show up until the next run.
    """
    descriptors = {spec["id"]: _check_descriptor(spec) for spec in CHECKS}
    return [{**result, **descriptors.get(result.get("id"), {})} for result in results]


async def _run_all() -> tuple[list[dict], int]:
    module = _load_check_module()
    writer = _TaskRoutingWriter()

    started = time.perf_counter()
    with contextlib.redirect_stdout(writer):
        results = await asyncio.gather(*(_run_one(module, spec, writer) for spec in CHECKS))
    elapsed_ms = round((time.perf_counter() - started) * 1000)

    return list(results), elapsed_ms


app = FastAPI(title="VulnHunter environment bridge")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
# Added after CORS, so it is the outermost layer and compresses the trace
# payloads too. Those are large by design now, and JSON this repetitive
# compresses by roughly an order of magnitude.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# The page reports the state of the environment as it is now, so there is
# exactly one reading worth keeping: the one on screen. Nothing is written
# down, and a restart starts from "not checked yet" rather than replaying a
# history nobody asked for.
_reading: dict | None = None


def _snapshot() -> dict:
    """The reading on screen: the checks, and when they were taken."""
    if _reading is None:
        return {"checks": _idle_results(), "lastRun": None}

    return {
        "checks": _with_current_descriptors(_reading["results"]),
        "lastRun": {
            "startedAt": _reading["startedAt"],
            "durationMs": _reading["durationMs"],
        },
    }


@app.get("/api/environment")
async def get_environment() -> dict:
    """The current state of the environment, without running anything."""
    _refresh_env()
    return _snapshot()


@app.post("/api/environment/check")
async def post_environment_check() -> dict:
    """Runs all five checks and replaces the reading. Takes as long as the
    slowest dependency."""
    global _reading

    _refresh_env()
    try:
        results, duration_ms = await _run_all()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"{type(exc).__name__}: {exc}") from exc

    _reading = {
        "startedAt": datetime.now().astimezone().isoformat(timespec="seconds"),
        "durationMs": duration_ms,
        "results": results,
    }
    return _snapshot()


# --------------------------------------------------------------------------- #
# Agent tracing
#
# `agent_tracing.py` in the repository root posts span events here from a
# background thread while the agent runs. Spans are kept in memory and grouped
# into traces by their root run id; nothing is persisted.
# --------------------------------------------------------------------------- #

MAX_TRACES = 50

_spans: dict[str, dict] = {}
_trace_order: list[str] = []
# Payloads are kept whole, so retention is bounded by size as well as by count.
_trace_bytes: dict[str, int] = {}
_bytes_total = 0
# Bumped on every applied event, so the dashboard can tell whether a trace it
# is polling actually changed without refetching the payloads to find out.
_revision: dict[str, int] = {}
# One small record per model span. Deliberately outside the byte budget: the
# token trend is a time series, and evicting traces must not erase its past.
_usage_samples: list[dict] = []


def _spans_of(trace_id: str) -> list[dict]:
    return [span for span in _spans.values() if span["traceId"] == trace_id]


def _drop_trace(trace_id: str) -> None:
    global _bytes_total
    for key in [key for key, item in _spans.items() if item["traceId"] == trace_id]:
        _bytes_total -= _spans[key].get("sizeBytes") or 0
        del _spans[key]
    _trace_bytes.pop(trace_id, None)
    _revision.pop(trace_id, None)


def _trim_payloads(trace_id: str) -> None:
    """Releases the bodies inside one oversized trace, oldest span first.

    The spans themselves stay, so the tree and the timings survive; only the
    payloads are replaced, and they say so rather than pretending to be empty.
    """
    global _bytes_total
    spans = sorted(_spans_of(trace_id), key=lambda span: span["startedAt"] or "")
    for span in spans:
        if _bytes_total <= MAX_TRACE_BYTES:
            return
        freed = span.get("sizeBytes") or 0
        if not freed:
            continue
        replacement = {"omitted": f"载荷超出内存预算，已释放约 {freed // 1024} KB"}
        span["inputs"] = replacement
        span["outputs"] = replacement
        span["sizeBytes"] = 0
        _bytes_total -= freed
        _trace_bytes[trace_id] = max(0, _trace_bytes.get(trace_id, 0) - freed)


def _evict() -> None:
    while len(_trace_order) > MAX_TRACES:
        _drop_trace(_trace_order.pop(0))

    while _bytes_total > MAX_TRACE_BYTES and _trace_order:
        if len(_trace_order) == 1:
            # A single audit larger than the whole budget: keep its shape.
            _trim_payloads(_trace_order[0])
            if _bytes_total > MAX_TRACE_BYTES:
                _drop_trace(_trace_order.pop(0))
            return
        _drop_trace(_trace_order.pop(0))


def _register_trace(trace_id: str) -> None:
    if trace_id in _trace_bytes:
        return
    _trace_order.append(trace_id)
    _trace_bytes[trace_id] = 0
    _revision[trace_id] = 0
    _evict()


def _record_usage(span: dict) -> None:
    usage = span.get("usage") or {}
    if not usage.get("totalTokens"):
        return
    _usage_samples.append({
        "startedAt": span.get("startedAt"),
        "model": span.get("model"),
        "usage": usage,
    })
    del _usage_samples[:-MAX_USAGE_SAMPLES]


def _summarise(trace_id: str) -> dict | None:
    spans = _spans_of(trace_id)
    if not spans:
        return None

    root = next((span for span in spans if span["parentId"] is None), spans[0])
    starts = [span["startedAt"] for span in spans if span["startedAt"]]
    ends = [span["endedAt"] for span in spans if span["endedAt"]]

    usage = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}
    for span in spans:
        for key in usage:
            usage[key] += (span.get("usage") or {}).get(key) or 0

    errors = sum(1 for span in spans if span["status"] == "error")
    running = any(span["status"] == "running" for span in spans)

    return {
        "id": trace_id,
        "name": root["name"],
        "startedAt": min(starts) if starts else root["startedAt"],
        "endedAt": max(ends) if ends else None,
        "status": "error" if errors else ("running" if running else "ok"),
        "spanCount": len(spans),
        "errorCount": errors,
        "usage": usage if usage["totalTokens"] else None,
        "revision": _revision.get(trace_id, 0),
        "sizeBytes": _trace_bytes.get(trace_id, 0),
    }


def _apply_event(event: dict) -> None:
    global _bytes_total
    span_id = event.get("spanId")
    if not span_id:
        return

    kind = event.get("type")

    if kind == "span.start":
        trace_id = event.get("traceId") or span_id
        size = int(event.get("sizeBytes") or 0)
        _spans[span_id] = {
            "id": span_id,
            "traceId": trace_id,
            "parentId": event.get("parentId"),
            "name": event.get("name") or event.get("kind") or "span",
            "kind": event.get("kind") or "chain",
            "startedAt": event.get("startedAt"),
            "endedAt": None,
            "status": "running",
            "inputs": event.get("inputs"),
            "outputs": None,
            "error": None,
            "model": event.get("model"),
            "usage": None,
            "tags": event.get("tags") or [],
            # Which LangGraph node the span belongs to, and whether `parentId`
            # had to be recovered from it. Kept so a trace can be diagnosed
            # after the fact without re-running anything.
            "graph": event.get("graph"),
            "adopted": bool(event.get("adopted")),
            "sizeBytes": size,
        }
        _bytes_total += size
        # Registered before the size is added: `_register_trace` uses presence in
        # `_trace_bytes` to mean "already known", so the byte must come second.
        _register_trace(trace_id)
        _trace_bytes[trace_id] = _trace_bytes.get(trace_id, 0) + size
        _revision[trace_id] = _revision.get(trace_id, 0) + 1
        return

    span = _spans.get(span_id)
    if span is None:
        return

    trace_id = span["traceId"]

    if kind == "span.end":
        span["endedAt"] = event.get("endedAt")
        span["status"] = "ok"
        if "outputs" in event:
            span["outputs"] = event["outputs"]
            size = int(event.get("sizeBytes") or 0)
            span["sizeBytes"] = (span.get("sizeBytes") or 0) + size
            _bytes_total += size
            _trace_bytes[trace_id] = _trace_bytes.get(trace_id, 0) + size
        if event.get("usage"):
            span["usage"] = event["usage"]
            _record_usage(span)
    elif kind == "span.error":
        span["endedAt"] = event.get("endedAt")
        span["status"] = "error"
        span["error"] = event.get("error")

    _revision[trace_id] = _revision.get(trace_id, 0) + 1
    _evict()


def _journal_events(events: list[dict]) -> None:
    """Appends a batch to the on-disk journal before it is acknowledged.

    Spans live in memory, but they are also written here so that a restart
    replays rather than loses them. `flush` hands the bytes to the OS right
    away; `fsync` is deliberately not used because it fails on the
    bind-mounted project directory this file lives in.

    The size check happens here rather than only at start-up: an audit now adds
    tens of megabytes, and the cap should bound the file while it is growing.
    A rotation keeps one previous generation and overwrites it in turn.
    """
    try:
        lines = [json.dumps(event, ensure_ascii=False, default=str) for event in events]
        incoming = sum(len(line) + 1 for line in lines)
        if JOURNAL.exists() and JOURNAL.stat().st_size + incoming > JOURNAL_MAX_BYTES:
            JOURNAL.replace(JOURNAL.parent / f"{JOURNAL.name}.1")

        with JOURNAL.open("a", encoding="utf-8") as handle:
            for line in lines:
                handle.write(line + chr(10))
            handle.flush()
    except OSError:
        # Tracing is a side channel; it must never break ingestion.
        pass


def _replay_file(path: Path) -> None:
    try:
        if not path.exists():
            return
        size = path.stat().st_size
        with path.open(encoding="utf-8") as handle:
            if size > REPLAY_MAX_BYTES:
                # Only the tail: the byte budget would evict the rest anyway,
                # and reading gigabytes to discard them is not a start-up cost
                # worth paying.
                handle.seek(size - REPLAY_MAX_BYTES)
                handle.readline()  # drop the partial line the seek landed in
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # A process killed mid-write can leave a partial last line.
                    continue
                if isinstance(event, dict):
                    _apply_event(event)
    except OSError:
        pass


def _replay_journal() -> None:
    """Rebuilds the in-memory store from the journal, once, at start-up."""
    # Oldest first, so that eviction order across the rotation boundary is the
    # same as it was while both were being written.
    _replay_file(JOURNAL.parent / f"{JOURNAL.name}.1")
    _replay_file(JOURNAL)


_replay_journal()


@app.post("/api/agent/events")
async def post_agent_events(events: list[dict]) -> dict:
    """Ingest a batch of span events from `agent_tracing.py`."""
    accepted = [event for event in events if isinstance(event, dict)]
    # Batches carry whole payloads now, so the journal write is real blocking
    # I/O rather than a few kilobytes.
    await asyncio.to_thread(_journal_events, accepted)
    for event in accepted:
        _apply_event(event)
    return {"accepted": len(events)}


@app.get("/api/agent/traces")
async def get_agent_traces() -> dict:
    """Trace summaries, newest first. Never carries payloads."""
    traces = [summary for trace_id in reversed(_trace_order) if (summary := _summarise(trace_id))]
    return {"traces": traces}


def _public_span(span: dict, payloads: bool) -> dict:
    if payloads:
        return span
    return {**span, "inputs": None, "outputs": None}


@app.get("/api/agent/traces/{trace_id}")
async def get_agent_trace(trace_id: str, payloads: bool = True) -> dict:
    """One trace with all its spans.

    `?payloads=false` returns the same tree without the bodies — that is what
    the dashboard polls, so a running audit does not re-send megabytes every
    few seconds. Payloads are then fetched one span at a time, on demand.
    """
    summary = _summarise(trace_id)
    if summary is None:
        raise HTTPException(status_code=404, detail=f"未找到轨迹 {trace_id}")
    return {**summary, "spans": [_public_span(span, payloads) for span in _spans_of(trace_id)]}


@app.get("/api/agent/traces/{trace_id}/spans/{span_id}")
async def get_agent_span(trace_id: str, span_id: str) -> dict:
    """A single span, with its payloads. The dashboard's detail view."""
    span = _spans.get(span_id)
    if span is None or span["traceId"] != trace_id:
        raise HTTPException(status_code=404, detail=f"未找到 span {span_id}")
    return span


@app.delete("/api/agent/traces")
async def clear_agent_traces() -> dict:
    """Empties the store — in memory *and* on disk.

    Clearing only memory used to look like it worked until the next restart,
    when the journal was replayed and everything came back.
    """
    global _bytes_total
    _spans.clear()
    _trace_order.clear()
    _trace_bytes.clear()
    _revision.clear()
    _usage_samples.clear()
    _bytes_total = 0

    removed = []
    for path in (JOURNAL, JOURNAL.parent / f"{JOURNAL.name}.1"):
        try:
            path.unlink(missing_ok=True)
            removed.append(str(path))
        except OSError:
            pass

    return {"cleared": True, "journalRemoved": removed}


# --------------------------------------------------------------------------- #
# Token usage
#
# Aggregated from the `usage` block of every model span the tracer has posted.
# Nothing is estimated: a provider that reports no cache fields simply produces
# zeroes there, and the dashboard renders "no data" for the hit rate.
# --------------------------------------------------------------------------- #

# Counted straight off the wire.
USAGE_FIELDS = ("inputTokens", "outputTokens", "totalTokens")

# Bucket sizes the usage trend can be grouped by, smallest first. Sent to the
# frontend so the selector's options come from here too.
USAGE_INTERVALS = (
    {"value": "1m", "label": "1 分钟", "seconds": 60},
    {"value": "15m", "label": "15 分钟", "seconds": 15 * 60},
    {"value": "1h", "label": "1 小时", "seconds": 60 * 60},
    {"value": "1d", "label": "1 天", "seconds": 24 * 60 * 60},
)
DEFAULT_USAGE_INTERVAL = "1h"

# Only meaningful when the provider actually reports caching; a provider that
# says nothing yields None here, never a zero.
CACHE_FIELDS = ("cacheReadTokens", "cacheCreationTokens")


def _zero_usage() -> dict:
    return {**dict.fromkeys(USAGE_FIELDS, 0), **dict.fromkeys(CACHE_FIELDS, 0), "cacheReported": False}


def _add_usage(target: dict, usage: dict) -> None:
    for field in USAGE_FIELDS:
        value = usage.get(field)
        if isinstance(value, (int, float)):
            target[field] += int(value)

    for field in CACHE_FIELDS:
        value = usage.get(field)
        if isinstance(value, (int, float)):
            target[field] += int(value)
            target["cacheReported"] = True


def _derive_usage(usage: dict, requests: int) -> dict:
    """Adds the numbers the dashboard shows but no provider reports directly.

    Two of them need the full picture rather than a single span:

    * ``newInputTokens`` — ``inputTokens`` already contains the cached ones, so
      what remains after removing them is genuinely new prompt text.
    * ``cacheHitRate`` — the share of input tokens served from cache, i.e.
      ``cacheReadTokens / inputTokens``. It is None both when no span reported
      cache fields at all and when nothing was sent, so the dashboard can say
      "no data" instead of inventing a 0%.
    """
    reported = usage.pop("cacheReported", False)

    if usage["totalTokens"] == 0:
        usage["totalTokens"] = usage["inputTokens"] + usage["outputTokens"]

    cache_read = usage["cacheReadTokens"] if reported else None
    cache_creation = usage["cacheCreationTokens"] if reported else None

    new_input = usage["inputTokens"] - (cache_read or 0) - (cache_creation or 0)

    return {
        "requests": requests,
        **usage,
        "cacheReadTokens": cache_read,
        "cacheCreationTokens": cache_creation,
        "newInputTokens": max(new_input, 0),
        "cacheHitRate": (
            round(cache_read / usage["inputTokens"] * 100, 1)
            if reported and usage["inputTokens"] > 0
            else None
        ),
    }


def _usage_bucket(iso: str, seconds: int) -> str:
    """The start of the interval-sized window a span falls in, as an ISO string.

    Normalising to UTC first means two spans describing the same instant with
    different offsets land in the same window. The label is deliberately not
    formatted here: the browser renders these in the reader's own timezone,
    which is what every other timestamp on the page already does.
    """
    try:
        moment = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    start = int(moment.timestamp()) // seconds * seconds
    return datetime.fromtimestamp(start, tz=timezone.utc).isoformat()


@app.get("/api/agent/usage")
async def get_agent_usage(interval: str = DEFAULT_USAGE_INTERVAL) -> dict:
    """Token totals and a bucketed series, across every stored trace."""
    chosen = next((item for item in USAGE_INTERVALS if item["value"] == interval), None)
    if chosen is None:
        raise HTTPException(status_code=400, detail=f"不支持的时间间隔 {interval}")
    # A separate, tiny per-model-span history rather than a scan of `_spans`:
    # the byte budget evicts traces, and the token trend should outlive them.
    samples = [sample for sample in _usage_samples if sample.get("usage")]
    options = [{"value": item["value"], "label": item["label"]} for item in USAGE_INTERVALS]

    if not samples:
        return {"totals": None, "models": [], "buckets": [], "interval": chosen["value"], "intervals": options}

    totals = _zero_usage()
    buckets: dict[str, dict] = {}

    for sample in samples:
        usage = sample["usage"]
        _add_usage(totals, usage)

        key = _usage_bucket(sample.get("startedAt") or "", chosen["seconds"])
        bucket = buckets.setdefault(key, {"key": key, "requests": 0, **_zero_usage()})
        bucket["requests"] += 1
        _add_usage(bucket, usage)

    models = sorted({sample["model"] for sample in samples if sample.get("model")})

    return {
        "totals": _derive_usage(totals, len(samples)),
        "models": models,
        "interval": chosen["value"],
        "intervals": options,
        "buckets": [
            _derive_usage(bucket, bucket.pop("requests"))
            for _, bucket in sorted(buckets.items())
        ],
    }


@app.get("/api/bridge/info")
async def get_bridge_info() -> dict:
    """How to start another instance of this service.

    Composed here rather than in the frontend so the command is correct by
    construction — it uses the interpreter actually running this process, which
    inside the devcontainer is the one that has the project's dependencies.
    """
    return {
        "command": f"cd {REPO_ROOT} && {sys.executable} web/server/main.py",
        "python": sys.executable,
        "port": int(os.getenv("BRIDGE_PORT", "8901")),
        "journal": str(JOURNAL),
    }


# --------------------------------------------------------------------------- #
# Audit tasks
#
# A task clones a repository at a given commit into AUDIT_ROOT and hands the
# checkout to `audit_agent.py`. Two properties of that script shape this code:
# `run()` starts a fixed-name container and reads a module-level PROJECT_ROOT,
# so only one audit can be in flight at a time; and it calls `asyncio.run()`,
# which cannot be nested inside the request loop, so tasks are processed by a
# worker thread rather than inline.
# --------------------------------------------------------------------------- #

MAX_TASKS = 50

# A task audits either the whole checkout or one function in it. The function
# mode additionally carries the file the function lives in, relative to the
# checkout root, and the function's own source.
AUDIT_MODES = ("project", "function")
# The source is echoed into the task journal on every state change and replayed
# at start-up, so it is bounded rather than accepted at whatever size it arrives.
MAX_FUNCTION_CODE_CHARS = 20_000
# `\w` is unicode-aware, so a filename with non-ASCII letters is still accepted;
# what this keeps out is whitespace and shell metacharacters.
FUNCTION_FILE_PATTERN = re.compile(r"^[\w.@+~/-]+$")

_tasks: dict[str, dict] = {}
_task_order: list[str] = []
_task_queue: "queue.Queue[str]" = queue.Queue()

_audit_module = None


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _journal_task(task: dict) -> None:
    """Appends the task's current state; replay keeps the last line per id."""
    try:
        with TASK_JOURNAL.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(task, ensure_ascii=False, default=str) + chr(10))
            handle.flush()
    except OSError:
        pass


def _replay_tasks() -> None:
    """Restores the task list, once, at start-up."""
    if not TASK_JOURNAL.exists():
        return

    try:
        if TASK_JOURNAL.stat().st_size > JOURNAL_MAX_BYTES:
            TASK_JOURNAL.replace(TASK_JOURNAL.parent / f"{TASK_JOURNAL.name}.1")
            return

        with TASK_JOURNAL.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    task = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(task, dict) and task.get("id"):
                    _tasks[task["id"]] = task
    except OSError:
        return

    _task_order[:] = sorted(_tasks, key=lambda task_id: _tasks[task_id].get("createdAt") or "")
    del _task_order[:-MAX_TASKS]

    # A task left mid-flight by a killed process is not running any more.
    for task in _tasks.values():
        if task.get("status") in ("queued", "cloning", "running"):
            task["status"] = "failed"
            task["error"] = "服务重启，任务中断"
            task["endedAt"] = task.get("endedAt") or _now_iso()
            _journal_task(task)


def _git(*args: str, timeout: float | None = None) -> None:
    """Runs git with an argv list (never a shell) and raises its last stderr line."""
    limit = GIT_TIMEOUT_S if timeout is None else timeout
    try:
        completed = subprocess.run(["git", *args], capture_output=True, text=True, timeout=limit)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git 超时（{int(limit)}s）") from exc

    if completed.returncode != 0:
        lines = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else f"git 退出码 {completed.returncode}")


def _clone(url: str, ref: str, target: Path) -> None:
    """Checks out one commit of a repository.

    A blobless clone fetches commits and trees only — django's full history is
    ~250 MB, this is a few tens of MB — and the checkout then pulls just the
    blobs that commit needs. The working tree ends up complete, which is all an
    audit reads; a history walk would fetch the rest on demand.
    """
    def fresh_clone(*extra: str) -> None:
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        # `--no-checkout` keeps the default branch out of the way; the wanted
        # commit is materialised by an explicit detached checkout below.
        _git("clone", "--no-checkout", *extra, "--", url, str(target))

    try:
        fresh_clone("--filter=blob:none")
    except RuntimeError:
        # Not every server supports partial clone; fall back to a full one.
        fresh_clone()

    _git("-C", str(target), "checkout", "--detach", ref)


def _validate_function_file(raw: str) -> str:
    """The function's file, as a repo-relative path with forward slashes.

    The path is handed to the agent and joined onto the checkout, so it is kept
    inside the checkout by construction: no absolute paths, no `..` segments.
    """
    path = raw.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]

    if not path:
        raise HTTPException(status_code=400, detail="函数所在的文件路径不能为空")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise HTTPException(status_code=400, detail="文件路径必须是相对项目根目录的路径, 不能是绝对路径")
    # Before the segment check: a path like `mod.py;ls /` also has a trailing
    # empty segment, and the charset is the more useful thing to report there.
    if not FUNCTION_FILE_PATTERN.match(path):
        raise HTTPException(status_code=400, detail="文件路径只能包含字母、数字、汉字和 . _ - @ + ~ / 这些字符")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise HTTPException(status_code=400, detail="文件路径不能包含空的、. 或 .. 的路径段")
    return path


def _load_audit_module():
    global _audit_module
    if _audit_module is None:
        if not AUDIT_SCRIPT.exists():
            raise RuntimeError(f"未找到 {AUDIT_SCRIPT}")
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        spec = importlib.util.spec_from_file_location("vulnhunter_audit_agent", AUDIT_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _audit_module = module
    return _audit_module


def _run_task(task_id: str) -> None:
    task = _tasks[task_id]
    checkout = AUDIT_ROOT / task_id

    try:
        _update_task(task_id, status="cloning", startedAt=_now_iso())
        _clone(task["url"], task["commit"], checkout)

        _update_task(task_id, status="running", checkout=str(checkout))

        module = _load_audit_module()
        module.PROJECT_ROOT = str(checkout)

        target = None
        if task.get("mode") == "function":
            file_path = task["filePath"]
            # The path is only known to be well-formed, not to exist: it is the
            # caller who says where the function lives. When it is not in this
            # commit the premise of the task is gone, and an agent that cannot
            # read the file would answer from the snippet alone — say so instead.
            if not (checkout / file_path).is_file():
                raise RuntimeError(f"在 commit {task['commit']} 的检出目录里找不到 {file_path}")
            target = module.FunctionTarget(file_path=file_path, code=task["functionCode"])

        verdict = (module.run(target) or "").strip()

        if not verdict:
            raise RuntimeError("agent 没有返回结论，详见容器日志")

        _update_task(task_id, status="done", verdict=verdict, endedAt=_now_iso())
    except Exception as exc:
        # A failed clone leaves a large partial pack behind; a failed agent run
        # leaves a checkout that is still worth keeping for inspection.
        if _tasks[task_id].get("status") == "cloning":
            shutil.rmtree(checkout, ignore_errors=True)

        _update_task(
            task_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            endedAt=_now_iso(),
        )


def _update_task(task_id: str, **changes) -> dict:
    task = _tasks[task_id]
    task.update(changes)
    _journal_task(task)
    return task


def _public_task(task: dict) -> dict:
    public = {
        key: task.get(key)
        for key in (
            "id", "url", "commit", "mode", "filePath", "functionCode",
            "status", "createdAt", "startedAt", "endedAt", "checkout", "verdict", "error",
        )
    }
    # `mode` arrived with function-level detection; every task journalled before
    # it audited the whole checkout, which is what the default says.
    public["mode"] = public["mode"] or "project"
    return public


def _audit_worker() -> None:
    while True:
        task_id = _task_queue.get()
        try:
            _run_task(task_id)
        finally:
            _task_queue.task_done()


@app.post("/api/audit/tasks")
async def post_audit_task(payload: dict) -> dict:
    """Queues a repository for auditing at a specific commit.

    `mode: "function"` narrows the audit to one function and therefore also
    requires `filePath` (relative to the checkout root) and `functionCode`.
    """
    url = str(payload.get("url") or "").strip()
    commit = str(payload.get("commit") or "").strip()
    mode = str(payload.get("mode") or "project").strip()

    if not URL_PATTERN.match(url):
        raise HTTPException(status_code=400, detail="仓库地址必须是 http(s)://、git://、ssh:// 或 git@ 形式的远程地址")
    if commit.startswith("-") or not REF_PATTERN.match(commit):
        raise HTTPException(status_code=400, detail="commit 必须是 4-120 位的分支名、标签或提交哈希")
    if mode not in AUDIT_MODES:
        raise HTTPException(status_code=400, detail="检测模式只能是项目检测或函数检测")

    file_path = None
    function_code = None

    if mode == "function":
        file_path = _validate_function_file(str(payload.get("filePath") or ""))
        # Only the blank lines around the snippet go: the function's own leading
        # indentation is part of what was submitted.
        function_code = str(payload.get("functionCode") or "").replace("\r\n", "\n").strip("\n\r")
        if not function_code.strip():
            raise HTTPException(status_code=400, detail="函数代码不能为空")
        if len(function_code) > MAX_FUNCTION_CODE_CHARS:
            raise HTTPException(
                status_code=400,
                detail=f"函数代码最多 {MAX_FUNCTION_CODE_CHARS} 个字符, 当前 {len(function_code)} 个",
            )

    task = {
        "id": f"audit-{int(time.time() * 1000)}",
        "url": url,
        "commit": commit,
        "mode": mode,
        "filePath": file_path,
        "functionCode": function_code,
        "status": "queued",
        "createdAt": _now_iso(),
        "startedAt": None,
        "endedAt": None,
        "checkout": None,
        "verdict": None,
        "error": None,
    }

    _tasks[task["id"]] = task
    _task_order.append(task["id"])
    del _task_order[:-MAX_TASKS]
    _journal_task(task)
    _task_queue.put(task["id"])

    return _public_task(task)


@app.get("/api/audit/tasks")
async def get_audit_tasks() -> dict:
    """Every task, newest first."""
    return {"tasks": [_public_task(_tasks[task_id]) for task_id in reversed(_task_order)]}


@app.get("/api/audit/tasks/{task_id}")
async def get_audit_task(task_id: str) -> dict:
    task = _tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"未找到任务 {task_id}")
    return _public_task(task)


_replay_tasks()
threading.Thread(target=_audit_worker, name="audit-worker", daemon=True).start()


if __name__ == "__main__":
    import uvicorn

    # Run this inside the devcontainer with `/home/vscode/.venv/bin/python`: that
    # is the only interpreter that has `check_environment.py`'s dependencies.
    # The host machine's Python does not, and the bridge will refuse to run the
    # checks there.
    uvicorn.run(
        app,
        host=os.getenv("BRIDGE_HOST", "127.0.0.1"),
        port=int(os.getenv("BRIDGE_PORT", "8901")),
    )