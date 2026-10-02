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
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_SCRIPT = REPO_ROOT / "check_environment.py"
ENV_FILE = REPO_ROOT / ".env"

# `evaluation.py` sits next to this file. It is imported by path rather than by
# package because this bridge is started as a script (`python web/server/main.py`),
# which puts `web/server/` on `sys.path` for a plain interpreter and not for a
# loader that execs this file from elsewhere (scripts/verify_*.py). Doing it here
# makes both entry points work the same way.
SERVER_DIR = Path(__file__).resolve().parent
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import evaluation  # noqa: E402  (needs the path setup above)
from trace_archive import TraceArchive, explicit_tool_failure  # noqa: E402

# The old rotating journal is read only during migration. New span events go
# into a per-trace archive in the project directory, which survives a container
# rebuild and is gitignored.
JOURNAL = Path(os.getenv("AGENT_TRACE_JOURNAL") or (REPO_ROOT / "agent_traces.jsonl"))
ARCHIVE_DIR = Path(os.getenv("AGENT_TRACE_ARCHIVE") or (JOURNAL.parent / f"{JOURNAL.stem}.archive"))
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
# The task journal still rotates. The old trace setting remains a fallback for
# deployments that relied on it to size this unrelated journal.
TASK_JOURNAL_MAX_BYTES = int(
    os.getenv("AUDIT_TASK_JOURNAL_MAX_MB") or os.getenv("AGENT_TRACE_JOURNAL_MAX_MB", "512")
) * 1024 * 1024
# Spans are cached whole, so this budget only governs memory eviction.
MAX_TRACE_BYTES = int(os.getenv("AGENT_TRACE_MAX_MB", "384")) * 1024 * 1024
# Only used by the legacy replay helper and its regression test.
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
# Active model configuration
# --------------------------------------------------------------------------- #

MODEL_PROVIDERS = {"openai", "deepseek", "qwen", "openrouter", "siliconflow", "custom"}
REASONING_EFFORT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _guess_model_provider(base_url: str) -> str:
    if not base_url.strip():
        return "openai"
    try:
        host = (urlsplit(base_url).hostname or "").lower()
    except ValueError:
        return "custom"
    if host == "api.openai.com":
        return "openai"
    if host == "api.deepseek.com":
        return "deepseek"
    if host.endswith("dashscope.aliyuncs.com"):
        return "qwen"
    if host == "openrouter.ai" or host.endswith(".openrouter.ai"):
        return "openrouter"
    if host.endswith("siliconflow.cn"):
        return "siliconflow"
    return "custom"


def _safe_model_base_url(base_url: str) -> str:
    """Hides credentials and query parameters if an older URL has any."""
    try:
        parsed_url = urlsplit(base_url)
        hostname = parsed_url.hostname
        if not hostname:
            return ""
        port = parsed_url.port
    except ValueError:
        return ""

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed_url.scheme, netloc, parsed_url.path, "", ""))


def _public_model_configuration() -> dict:
    base_url = os.getenv("OPENAI_BASE_URL", "") or ""
    provider = os.getenv("MODEL_PROVIDER", "") or _guess_model_provider(base_url)
    if provider not in MODEL_PROVIDERS:
        provider = "custom"
    return {
        "provider": provider,
        "modelName": os.getenv("MODEL_NAME", "") or "",
        "reasoningEffort": os.getenv("MODEL_REASONING_EFFORT", "none").strip() or "none",
        "baseUrl": _safe_model_base_url(base_url),
        "apiKeyConfigured": bool(os.getenv("OPENAI_API_KEY")),
    }


@app.get("/api/model/config")
async def get_model_configuration() -> dict:
    """Returns active model settings, excluding the stored API key."""
    _refresh_env()
    return _public_model_configuration()


@app.put("/api/model/config")
async def put_model_configuration(payload: dict) -> dict:
    """Updates .env and the running bridge so newly created agents use it."""
    _refresh_env()
    provider = str(payload.get("provider") or "").strip()
    model_name = str(payload.get("modelName") or "").strip()
    reasoning_effort_value = payload.get("reasoningEffort", "none")
    if not isinstance(reasoning_effort_value, str):
        raise HTTPException(status_code=400, detail="请选择有效的推理强度")
    reasoning_effort = reasoning_effort_value.strip()
    base_url = str(payload.get("baseUrl") or "").strip()
    api_key_value = payload.get("apiKey", "")
    clear_api_key = payload.get("clearApiKey", False) is True

    if provider not in MODEL_PROVIDERS:
        raise HTTPException(status_code=400, detail="请选择有效的模型服务商")
    if not model_name or len(model_name) > 200:
        raise HTTPException(status_code=400, detail="模型名称不能为空，且不能超过 200 个字符")
    if not REASONING_EFFORT_PATTERN.fullmatch(reasoning_effort):
        raise HTTPException(status_code=400, detail="推理强度只能包含字母、数字、下划线、点或连字符，最多 64 个字符")
    if len(base_url) > 2000:
        raise HTTPException(status_code=400, detail="API 地址不能超过 2000 个字符")
    if base_url:
        try:
            parsed_url = urlsplit(base_url)
            port = parsed_url.port
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="API 地址包含无效的主机或端口") from exc
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.fragment
            or parsed_url.query
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise HTTPException(status_code=400, detail="API 地址必须是有效的 HTTP(S) 地址，认证信息请填写在 API Key 中")
        base_url = base_url.rstrip("/")
    elif provider != "openai":
        raise HTTPException(status_code=400, detail="该服务商需要填写 API 地址")
    if not isinstance(api_key_value, str):
        raise HTTPException(status_code=400, detail="API Key 格式无效")
    api_key = api_key_value.strip()
    if len(api_key) > 8192:
        raise HTTPException(status_code=400, detail="API Key 不能超过 8192 个字符")
    if clear_api_key and api_key:
        raise HTTPException(status_code=400, detail="清除密钥时请留空 API Key 输入框")
    if not api_key and not os.getenv("OPENAI_API_KEY") and not clear_api_key:
        raise HTTPException(status_code=400, detail="请填写 API Key")

    try:
        from dotenv import set_key, unset_key

        ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        set_key(ENV_FILE, "MODEL_PROVIDER", provider, quote_mode="auto")
        set_key(ENV_FILE, "MODEL_NAME", model_name, quote_mode="auto")
        set_key(ENV_FILE, "MODEL_REASONING_EFFORT", reasoning_effort, quote_mode="auto")
        set_key(ENV_FILE, "OPENAI_BASE_URL", base_url, quote_mode="auto")
        if clear_api_key:
            unset_key(ENV_FILE, "OPENAI_API_KEY")
            os.environ.pop("OPENAI_API_KEY", None)
        elif api_key:
            set_key(ENV_FILE, "OPENAI_API_KEY", api_key, quote_mode="auto")
            os.environ["OPENAI_API_KEY"] = api_key
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="当前 Python 环境缺少 python-dotenv，无法保存配置") from exc
    except OSError as exc:
        raise HTTPException(status_code=500, detail="模型配置写入失败，请检查工作区 .env 文件权限") from exc

    os.environ["MODEL_PROVIDER"] = provider
    os.environ["MODEL_NAME"] = model_name
    os.environ["MODEL_REASONING_EFFORT"] = reasoning_effort
    os.environ["OPENAI_BASE_URL"] = base_url
    _refresh_env()
    return _public_model_configuration()


# --------------------------------------------------------------------------- #
# Agent tracing
#
# `agent_tracing.py` posts span events here from a background thread. The
# bounded span store below is only a cache; TraceArchive owns the full history.
# --------------------------------------------------------------------------- #

MAX_TRACES = 50
_archive = TraceArchive(ARCHIVE_DIR)
_trace_ingest_lock = asyncio.Lock()

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


def _propagated_errors(spans: list[dict]) -> set[str]:
    """Ids of the spans that only carry a descendant's exception upward.

    A raising run reports the same exception on each enclosing span, so the
    failure belongs to the *deepest* span in that chain — the one it was raised
    in — and the spans above it are on its path rather than at fault. The error
    text identifies a chain: propagation repeats it verbatim, while two
    independent failures that happen to nest each have their own.

    Every span with such a descendant is marked here, which leaves the count as
    the number of spans *unmarked*. Walking up from each errored span, rather
    than down from each of them, keeps this linear in the chain depths.
    """
    by_id = {span["id"]: span for span in spans}
    chains: dict[str, list[dict]] = {}
    for span in spans:
        if span["status"] == "error":
            chains.setdefault(span.get("error") or "", []).append(span)

    propagated: set[str] = set()
    for chain in chains.values():
        ids = {span["id"] for span in chain}
        for span in chain:
            parent_id = span.get("parentId")
            while parent_id:
                ancestor = by_id.get(parent_id)
                if ancestor is None:
                    # Parent unknown (evicted or never reported): nothing above
                    # it can be shown to belong to this chain.
                    break
                if ancestor["id"] in ids:
                    propagated.add(ancestor["id"])
                parent_id = ancestor.get("parentId")

    return propagated


def _count_failures(spans: list[dict]) -> int:
    """Counts distinct failures, not every span an exception crossed."""
    propagated = _propagated_errors(spans)
    return sum(
        1
        for span in spans
        if span["status"] == "error" and span["id"] not in propagated
    )


def _spans_with_error_origin(trace_id: str, payloads: bool) -> list[dict]:
    """Public spans, each tagged with whether the failure is its own.

    The dashboard needs that tag as much as the count does: with one failure
    reported on four spans, an undifferentiated red marker on all four reads as
    four failures — and none of them says which one to look at.
    """
    spans = _spans_of(trace_id)
    propagated = _propagated_errors(spans)
    return [
        {**_public_span(span, payloads), "propagated": span["id"] in propagated}
        for span in spans
    ]


def _trace_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _last_span_activity(spans: list[dict]) -> str | None:
    latest: tuple[datetime, str] | None = None
    for span in spans:
        for raw in (span.get("startedAt"), span.get("endedAt")):
            moment = _trace_time(raw)
            if moment is not None and (latest is None or moment > latest[0]):
                latest = (moment, raw)
    return latest[1] if latest else None


def _same_job_attempt(summary: dict, job: dict) -> bool:
    """Retries reuse a sample id, but each trace belongs to only one attempt."""
    job_start = _trace_time(job.get("startedAt"))
    trace_start = _trace_time(summary.get("startedAt"))
    return job_start is None or trace_start is None or trace_start >= job_start


def _overlay_job_state(summary: dict, job_id: str | None, last_activity_at) -> dict:
    if not job_id:
        return summary
    job = _tasks.get(job_id) or evaluation.get_sample(job_id)
    job_status = job.get("status") if job else None
    current = bool(job and job_status in ("running", "done", "failed", "cancelled")
                   and _same_job_attempt(summary, job))
    with _job_cancel_lock:
        cancel_event = _job_cancel_events.get(job_id) if current and job_status == "running" else None
        summary["stopRequested"] = bool(cancel_event and cancel_event.is_set())
        summary["canStop"] = bool(cancel_event and not cancel_event.is_set())

    if current:
        if job_status == "running":
            # Root spans can close before the worker finishes post-processing.
            summary["status"] = "running"
            summary["endedAt"] = None
        else:
            summary["endedAt"] = job.get("endedAt") or summary["endedAt"] or last_activity_at()
            if job_status == "cancelled":
                summary["status"] = "cancelled"
            elif job_status == "failed":
                summary["status"] = "error"
            else:
                summary["status"] = "error" if summary["errorCount"] else "ok"
    elif summary["status"] == "running":
        # A forgotten or previous managed attempt has no live worker. This is
        # an API projection; the original span events remain in the archive.
        summary["status"] = "interrupted"
        summary["endedAt"] = last_activity_at() or summary["startedAt"]
    return summary


def _project_incomplete_span(span: dict, summary: dict) -> dict:
    if span["status"] == "running" and summary["status"] != "running" and summary.get("endedAt"):
        return {**span, "status": "interrupted", "endedAt": summary["endedAt"]}
    return span


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

    errors = _count_failures(spans)
    running = any(span["status"] == "running" for span in spans)
    job_id = next(
        (tag.removeprefix("bridge-job:") for tag in root.get("tags", []) if tag.startswith("bridge-job:")),
        None,
    )
    summary = {
        "id": trace_id,
        "name": root["name"],
        "startedAt": min(starts) if starts else root["startedAt"],
        "endedAt": None if running else (max(ends) if ends else None),
        "status": "running" if running else ("error" if errors else "ok"),
        "canStop": False,
        "stopRequested": False,
        "spanCount": len(spans),
        "errorCount": errors,
        "usage": usage if usage["totalTokens"] else None,
        "revision": _revision.get(trace_id, 0),
        "sizeBytes": _trace_bytes.get(trace_id, 0),
    }
    return _overlay_job_state(summary, job_id, lambda: _last_span_activity(spans))


def _public_archived_summary(stored: dict) -> dict:
    """Overlay the current job state on a durable trace summary."""
    summary = {key: value for key, value in stored.items() if not key.startswith("_")}
    return _overlay_job_state(summary, stored.get("_jobId"),
                              lambda: _archive.last_activity_at(stored["id"]))


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
        failure = (
            explicit_tool_failure(event.get("outputs"), span["name"])
            if span["kind"] == "tool"
            else None
        )
        span["status"] = "error" if failure else "ok"
        span["error"] = failure
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


def _replay_file(path: Path) -> None:
    """Legacy tail parser retained for old-log diagnostics and its test."""
    try:
        if not path.exists():
            return
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > REPLAY_MAX_BYTES:
                # Only the tail: the byte budget would evict the rest anyway,
                # and reading gigabytes to discard them is not a start-up cost
                # worth paying.
                start = size - REPLAY_MAX_BYTES
                handle.seek(start - 1)
                if handle.read(1) != b"\n":
                    handle.readline()  # drop only a partial JSONL record
            for raw_line in handle:
                if not raw_line.strip():
                    continue
                try:
                    event = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # A process killed mid-write can leave a damaged record.
                    continue
                if isinstance(event, dict):
                    _apply_event(event)
    except OSError:
        pass


@app.post("/api/agent/events")
async def post_agent_events(events: list[dict]) -> dict:
    """Ingest a batch of span events from `agent_tracing.py`."""
    accepted = [event for event in events if isinstance(event, dict)]
    # Serialize write/apply order. Concurrent requests can otherwise put an end
    # event on disk before its start and corrupt both the tree and the index.
    async with _trace_ingest_lock:
        persisted = await asyncio.to_thread(_archive.append, accepted)
        for event in persisted:
            _apply_event(event)
    return {"accepted": len(persisted)}


@app.get("/api/agent/traces")
async def get_agent_traces() -> dict:
    """Trace summaries, newest first. Never carries payloads."""
    traces = [_public_archived_summary(item) for item in await asyncio.to_thread(_archive.list_summaries)]
    # Direct `_apply_event` callers (legacy replay and local verification
    # harnesses) can have cache-only traces. Live HTTP ingestion always archives.
    known = {item["id"] for item in traces}
    traces.extend(summary for trace_id in reversed(_trace_order)
                  if trace_id not in known and (summary := _summarise(trace_id)))
    traces.sort(key=lambda item: item.get("startedAt") or "", reverse=True)
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
    stored = await asyncio.to_thread(_archive.get_summary, trace_id)
    if stored is None:
        summary = _summarise(trace_id)
        if summary is None:
            raise HTTPException(status_code=404, detail=f"未找到轨迹 {trace_id}")
        spans = _spans_with_error_origin(trace_id, payloads)
        return {**summary, "spans": [_project_incomplete_span(span, summary) for span in spans]}
    summary = _public_archived_summary(stored)
    cached = _spans_of(trace_id)
    if len(cached) == summary["spanCount"] and _revision.get(trace_id) == summary["revision"] and (
        not payloads or all(not isinstance(span.get("inputs"), dict) or "omitted" not in span["inputs"]
                            for span in cached)
    ):
        spans = _spans_with_error_origin(trace_id, payloads)
    else:
        archived = await asyncio.to_thread(_archive.read_trace, trace_id, payloads)
        if archived is None:
            raise HTTPException(status_code=404, detail=f"未找到轨迹 {trace_id}")
        propagated = _propagated_errors(archived)
        spans = [{**span, "propagated": span["id"] in propagated} for span in archived]
    return {**summary, "spans": [_project_incomplete_span(span, summary) for span in spans]}


@app.post("/api/agent/traces/{trace_id}/stop")
async def stop_agent_trace(trace_id: str) -> dict:
    """Requests cancellation only for an active job owned by this bridge."""
    stored = await asyncio.to_thread(_archive.get_summary, trace_id)
    if stored is None:
        summary = _summarise(trace_id)
        if summary is None:
            raise HTTPException(status_code=404, detail=f"未找到轨迹 {trace_id}")
        spans = _spans_of(trace_id)
        root = next((span for span in spans if span["parentId"] is None), spans[0])
        job_id = next((tag.removeprefix("bridge-job:") for tag in root.get("tags", [])
                       if tag.startswith("bridge-job:")), None)
    else:
        job_id = stored.get("_jobId")
        summary = stored
    if not job_id:
        raise HTTPException(status_code=409, detail="这条轨迹不是桥接服务启动的任务，无法停止")
    with _job_cancel_lock:
        cancel_event = _job_cancel_events.get(job_id)
        job = _tasks.get(job_id) or evaluation.get_sample(job_id)
        if (cancel_event is None or not job or job.get("status") != "running"
                or not _same_job_attempt(summary, job)):
            raise HTTPException(status_code=409, detail="任务已经结束，无法停止")
        cancel_event.set()
    return {"stopRequested": True}


@app.get("/api/agent/traces/{trace_id}/spans/{span_id}")
async def get_agent_span(trace_id: str, span_id: str) -> dict:
    """A single span, with its payloads. The dashboard's detail view."""
    stored = await asyncio.to_thread(_archive.get_summary, trace_id)
    if stored is None:
        span = _spans.get(span_id)
        if span is None or span["traceId"] != trace_id:
            raise HTTPException(status_code=404, detail=f"未找到 span {span_id}")
        summary = _summarise(trace_id)
        propagated = _propagated_errors(_spans_of(trace_id))
        return _project_incomplete_span({**span, "propagated": span["id"] in propagated}, summary)
    summary = _public_archived_summary(stored)
    cached = _spans_of(trace_id)
    span = _spans.get(span_id)
    if span is not None and len(cached) == stored["spanCount"] and _revision.get(trace_id) == stored["revision"] and not (
        isinstance(span.get("inputs"), dict) and "omitted" in span["inputs"]
    ):
        spans = cached
    else:
        spans = await asyncio.to_thread(_archive.read_trace, trace_id, True) or []
        span = next((item for item in spans if item["id"] == span_id), None)
    if span is None or span["traceId"] != trace_id:
        raise HTTPException(status_code=404, detail=f"未找到 span {span_id}")
    # Same tag as the tree carries, or the sheet would lose it the moment the
    # span is refetched for its payloads.
    propagated = _propagated_errors(spans)
    return _project_incomplete_span({**span, "propagated": span["id"] in propagated}, summary)


@app.delete("/api/agent/traces")
async def clear_agent_traces() -> dict:
    """Empties the store — in memory *and* on disk.

    Clearing only memory used to look like it worked until the next restart,
    when the journal was replayed and everything came back.
    """
    global _bytes_total
    async with _trace_ingest_lock:
        removed = await asyncio.to_thread(_archive.clear)
        _spans.clear()
        _trace_order.clear()
        _trace_bytes.clear()
        _revision.clear()
        _usage_samples.clear()
        _bytes_total = 0
        for path in [*JOURNAL.parent.glob(f"{JOURNAL.name}.saved-*.jsonl"),
                     JOURNAL.parent / f"{JOURNAL.name}.1", JOURNAL]:
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
        "archive": str(ARCHIVE_DIR),
    }


# --------------------------------------------------------------------------- #
# Audit tasks
#
# A task clones a repository at a given commit into AUDIT_ROOT and hands the
# checkout to `audit_agent.py`. Each invocation gets its own project root,
# container, and result files. The agent calls `asyncio.run()`, which cannot be
# nested inside the request loop, so jobs run in a bounded worker pool.
# --------------------------------------------------------------------------- #

MAX_TASKS = 50
_refresh_env()
MIN_AUDIT_CONCURRENCY = 1
MAX_AUDIT_CONCURRENCY = 16
try:
    AUDIT_MAX_CONCURRENCY = int(os.getenv("AUDIT_MAX_CONCURRENCY", "2"))
except ValueError as exc:
    raise RuntimeError(f"AUDIT_MAX_CONCURRENCY 必须是 {MIN_AUDIT_CONCURRENCY} 到 {MAX_AUDIT_CONCURRENCY} 之间的整数") from exc
if not MIN_AUDIT_CONCURRENCY <= AUDIT_MAX_CONCURRENCY <= MAX_AUDIT_CONCURRENCY:
    raise RuntimeError(f"AUDIT_MAX_CONCURRENCY 必须是 {MIN_AUDIT_CONCURRENCY} 到 {MAX_AUDIT_CONCURRENCY} 之间的整数")

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
_job_cancel_events: dict[str, threading.Event] = {}
_job_cancel_lock = threading.Lock()
_task_journal_lock = threading.Lock()
_worker_condition = threading.Condition()
_concurrency_update_lock = asyncio.Lock()
_active_worker_count = 0
_worker_threads: set[threading.Thread] = set()
_worker_serial = 0

_audit_module = None
_audit_module_lock = threading.Lock()


def _ensure_worker_threads(count: int) -> None:
    """Match worker capacity to the configured concurrency without a restart."""
    global _worker_serial
    while len(_worker_threads) < count:
        _worker_serial += 1
        worker = threading.Thread(
            target=_audit_worker,
            name=f"audit-worker-{_worker_serial}",
            daemon=True,
        )
        _worker_threads.add(worker)
        try:
            worker.start()
        except Exception:
            _worker_threads.discard(worker)
            raise


@app.get("/api/settings/concurrency")
async def get_concurrency_configuration() -> dict:
    """Returns the live task limit shared by audits and evaluations."""
    return {"maxConcurrency": AUDIT_MAX_CONCURRENCY}


def _apply_joern_concurrency(value: int) -> None:
    """Update the live CodeBadger pool before allowing more audit workers."""
    parsed = urlsplit(os.getenv("CodeBadger_URL") or "")
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError("CodeBadger_URL 未配置，无法同步 Joern 并行数量")
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, "/settings/joern/concurrency", "", ""))
    body = json.dumps({"maxActiveServers": value}).encode("utf-8")
    request = Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="PUT")
    try:
        with urlopen(request, timeout=15) as response:
            result = json.load(response)
    except HTTPError as exc:
        if exc.code == 400:
            try:
                detail = json.load(exc).get("error", "Joern 并行数量无效")
            except (ValueError, AttributeError):
                detail = "Joern 并行数量无效"
            raise ValueError(detail) from exc
        raise
    if result.get("maxActiveServers") != value:
        raise RuntimeError("CodeBadger 未确认 Joern 并行数量")


@app.put("/api/settings/concurrency")
async def put_concurrency_configuration(payload: dict) -> dict:
    """Apply one limit to both the audit workers and the Joern pool."""
    global AUDIT_MAX_CONCURRENCY

    max_concurrency = payload.get("maxConcurrency")
    if type(max_concurrency) is not int or not MIN_AUDIT_CONCURRENCY <= max_concurrency <= MAX_AUDIT_CONCURRENCY:
        raise HTTPException(
            status_code=400,
            detail=f"最大并行数量必须是 {MIN_AUDIT_CONCURRENCY} 到 {MAX_AUDIT_CONCURRENCY} 之间的整数",
        )

    async with _concurrency_update_lock:
        _refresh_env()
        previous = AUDIT_MAX_CONCURRENCY
        try:
            await asyncio.to_thread(_apply_joern_concurrency, max_concurrency)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="CodeBadger 不可用，未更改并行数量") from exc

        try:
            from dotenv import set_key

            ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
            set_key(ENV_FILE, "AUDIT_MAX_CONCURRENCY", str(max_concurrency), quote_mode="auto")
        except (ImportError, OSError) as exc:
            try:
                await asyncio.to_thread(_apply_joern_concurrency, previous)
            except Exception:
                print("[audit] 无法回退 CodeBadger Joern 并行数量", flush=True)
            detail = ("当前 Python 环境缺少 python-dotenv，无法保存配置" if isinstance(exc, ImportError)
                      else "并行数量写入失败，请检查工作区 .env 文件权限")
            raise HTTPException(status_code=503 if isinstance(exc, ImportError) else 500, detail=detail) from exc

        os.environ["AUDIT_MAX_CONCURRENCY"] = str(max_concurrency)
        with _worker_condition:
            AUDIT_MAX_CONCURRENCY = max_concurrency
            _ensure_worker_threads(max_concurrency)
            _worker_condition.notify_all()
    return {"maxConcurrency": AUDIT_MAX_CONCURRENCY}


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _journal_task(task: dict) -> None:
    """Appends the task's current state; replay keeps the last line per id."""
    try:
        with _task_journal_lock:
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
        if TASK_JOURNAL.stat().st_size > TASK_JOURNAL_MAX_BYTES:
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
        if not _remove_checkout(target):
            raise RuntimeError(f"无法清理旧检出目录 {target}")
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
    with _audit_module_lock:
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


def _remove_checkout(checkout: Path) -> bool:
    try:
        shutil.rmtree(checkout)
        return True
    except FileNotFoundError:
        return True
    except PermissionError:
        # The audit container may leave root-owned files (notably __pycache__)
        # behind when it is interrupted. The bridge runs as vscode and cannot
        # remove those files itself. Clean only this job's checkout through the
        # same Docker image used by the audit, then remove the owned top level.
        if checkout.is_symlink() or checkout.parent.resolve() != AUDIT_ROOT.resolve():
            print(f"[audit] 拒绝清理非任务检出目录 {checkout}", flush=True)
            return False
        try:
            import docker

            client = docker.from_env()
            try:
                client.containers.run(
                    "mcr.microsoft.com/devcontainers/anaconda:3",
                    ["find", "/workspace", "-mindepth", "1", "-delete"],
                    volumes={str(checkout): {"bind": "/workspace", "mode": "rw"}},
                    user="root",
                    remove=True,
                )
            finally:
                client.close()
            shutil.rmtree(checkout)
            return True
        except Exception as exc:
            print(f"[audit] 清理检出目录失败 {checkout}: {exc}", flush=True)
            return False
    except OSError as exc:
        print(f"[audit] 清理检出目录失败 {checkout}: {exc}", flush=True)
        return False


def _run_task(task_id: str) -> None:
    task = _tasks[task_id]
    checkout = AUDIT_ROOT / task_id
    cancel_event = _job_cancel_events[task_id]

    try:
        _update_task(task_id, status="cloning", startedAt=_now_iso())
        _clone(task["url"], task["commit"], checkout)
        if cancel_event.is_set():
            raise asyncio.CancelledError()

        _update_task(task_id, status="running", checkout=str(checkout))

        module = _load_audit_module()

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

        verdict = (
            module.run(
                target,
                project_root=str(checkout),
                output_path=str(AUDIT_ROOT / ".results" / f"{task_id}.txt"),
                job_id=task_id,
                cancel_event=cancel_event,
                cleanup_checkout=True,
            )
            or ""
        ).strip()
        if cancel_event.is_set():
            raise asyncio.CancelledError()

        if not verdict:
            raise RuntimeError("agent 没有返回结论，详见容器日志")

        assessment = module.parse_audit_result(verdict)
        _update_task(
            task_id,
            status="done",
            verdict=assessment.model_dump(mode="json"),
            endedAt=_now_iso(),
        )
    except asyncio.CancelledError:
        _update_task(task_id, status="cancelled", error="已停止", endedAt=_now_iso())
    except Exception as exc:
        _update_task(
            task_id,
            status="cancelled" if cancel_event.is_set() else "failed",
            error="已停止" if cancel_event.is_set() else f"{type(exc).__name__}: {exc}",
            endedAt=_now_iso(),
        )
    finally:
        if _remove_checkout(checkout) and _tasks[task_id].get("checkout") is not None:
            _update_task(task_id, checkout=None)


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
    global _active_worker_count

    worker = threading.current_thread()
    while True:
        with _worker_condition:
            if len(_worker_threads) > AUDIT_MAX_CONCURRENCY:
                _worker_threads.discard(worker)
                _worker_condition.notify_all()
                return

        try:
            task_id = _task_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            retire = False
            with _worker_condition:
                while _active_worker_count >= AUDIT_MAX_CONCURRENCY:
                    if len(_worker_threads) > AUDIT_MAX_CONCURRENCY:
                        _worker_threads.discard(worker)
                        _worker_condition.notify_all()
                        retire = True
                        break
                    _worker_condition.wait()
                if not retire:
                    _active_worker_count += 1

            if retire:
                # Put the claimed job back before this excess worker exits.
                _task_queue.put(task_id)
                return

            try:
                with _job_cancel_lock:
                    _job_cancel_events[task_id] = threading.Event()
                # Both job types share a bounded worker pool. Its live limit can
                # change from the settings page without interrupting active jobs.
                if evaluation.get_sample(task_id) is not None:
                    _run_eval_sample(task_id)
                else:
                    _run_task(task_id)
            except Exception:
                # Both job runners catch the failures they expect, so this is the net
                # for everything else: a surprise has to kill the job, not the
                # thread. A dead worker means a queue that never moves again, and the
                # job it was holding is the one nobody is watching.
                traceback.print_exc()
            finally:
                with _job_cancel_lock:
                    _job_cancel_events.pop(task_id, None)
                with _worker_condition:
                    _active_worker_count -= 1
                    _worker_condition.notify_all()
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
        "id": f"audit-{uuid.uuid4().hex}",
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


# --------------------------------------------------------------------------- #
# Benchmark evaluation
#
# A run is a scope resolved against a dataset (RepoPairBench, in `benchmark/`)
# into a list of (item, type) samples. Each sample is executed exactly like a
# function-level audit — same checkout, same agent, same container — with two
# differences: the vulnerable side checks out the *parent* of the fixing commit,
# and the agent is asked for a structured verdict so the answer can be scored.
#
# Samples go on the same bounded worker pool as audit tasks, so benchmark runs
# can overlap with each other and with normal audits.
# --------------------------------------------------------------------------- #


def _run_eval_sample(sample_id: str) -> None:
    sample = evaluation.get_sample(sample_id)
    if sample is None or not evaluation.claim_sample(sample_id, _now_iso()):
        return
    cancel_event = _job_cancel_events[sample_id]

    run = evaluation.get_run(sample["runId"])
    dataset = evaluation.datasets().get(run["datasetId"]) if run else None

    checkout = AUDIT_ROOT / sample_id

    try:
        if dataset is None:
            evaluation.update_sample(
                sample_id, status="failed", error="数据集不可用", endedAt=_now_iso(),
            )
            return

        spec = evaluation.sample_input(dataset, sample["itemId"], sample["type"])
        # The run follows its samples: this is what moves it off `queued`.
        evaluation.refresh_run_status(sample["runId"])
        _clone(spec["url"], spec["ref"], checkout)
        if cancel_event.is_set():
            raise asyncio.CancelledError()

        # The dataset says where the function lives; only a read of the checkout
        # can confirm it is there. Missing means the sample's premise is gone and
        # an agent would answer from the snippet alone.
        if not (checkout / spec["filePath"]).is_file():
            raise RuntimeError(f"在 {spec['ref']} 的检出目录里找不到 {spec['filePath']}")

        evaluation.update_sample(sample_id, status="running", checkout=str(checkout))

        module = _load_audit_module()

        target = module.FunctionTarget(file_path=spec["filePath"], code=spec["code"])
        verdict = (
            module.run(
                target,
                project_root=str(checkout),
                output_path=str(AUDIT_ROOT / ".results" / f"{sample_id}.txt"),
                job_id=sample_id,
                cancel_event=cancel_event,
                cleanup_checkout=True,
            )
            or ""
        ).strip()
        if cancel_event.is_set():
            raise asyncio.CancelledError()

        if not verdict:
            raise RuntimeError("agent 没有返回结论，详见容器日志")

        try:
            assessment = module.parse_audit_result(verdict)
        except (TypeError, ValueError):
            # A completed model call with malformed structured output is a miss,
            # not a guessed label or an infrastructure failure.
            evaluation.update_sample(
                sample_id,
                status="done",
                verdict=verdict,
                prediction=None,
                endedAt=_now_iso(),
            )
            return

        evaluation.update_sample(
            sample_id,
            status="done",
            verdict=assessment.model_dump(mode="json"),
            prediction=module.prediction_label(assessment.verdict),
            endedAt=_now_iso(),
        )
    except asyncio.CancelledError:
        evaluation.update_sample(sample_id, status="cancelled", error="已停止", endedAt=_now_iso())
    except Exception as exc:
        evaluation.update_sample(
            sample_id,
            status="cancelled" if cancel_event.is_set() else "failed",
            error="已停止" if cancel_event.is_set() else f"{type(exc).__name__}: {exc}",
            endedAt=_now_iso(),
        )
    finally:
        # audit_agent.run() removes the container before returning. Delete the
        # host checkout for every terminal path, including cancellation/errors.
        checkout_removed = _remove_checkout(checkout)
        current_sample = evaluation.get_sample(sample_id)
        if checkout_removed and current_sample is not None and current_sample.get("checkout") is not None:
            evaluation.update_sample(sample_id, checkout=None)
        evaluation.refresh_run_status(sample["runId"])


def _require_dataset(dataset_id: str):
    dataset = evaluation.datasets().get(dataset_id)
    if dataset is None:
        raise HTTPException(status_code=404, detail=f"未找到数据集 {dataset_id}，请确认 benchmark/ 下有对应的文件")
    return dataset


def _require_scope(payload: dict) -> dict:
    scope = payload.get("scope")
    if scope is None:
        scope = {}
    if not isinstance(scope, dict):
        raise HTTPException(status_code=400, detail="scope 必须是一个对象")
    return scope


@app.get("/api/eval/datasets")
async def get_eval_datasets() -> dict:
    """The datasets this bridge can evaluate, without their items."""
    available = evaluation.datasets(refresh=True)
    return {
        "datasets": [
            {
                "id": dataset.id,
                "name": dataset.name,
                "description": dataset.description,
                "itemCount": len(dataset.items),
                "typeOptions": [dict(option) for option in evaluation.TYPE_OPTIONS],
            }
            for dataset in available.values()
        ],
    }


@app.get("/api/eval/datasets/{dataset_id}/items")
async def get_eval_dataset_items(
    dataset_id: str,
    project: list[str] = Query(default=[]),
    cwe: list[str] = Query(default=[]),
    search: str = "",
) -> dict:
    """The pairs in a dataset, filtered.

    The filtering happens here rather than in the page so there is one
    implementation of it: the rows the table shows are produced by the same
    predicate that resolves a scope, so "全选这些行" cannot select something the
    run would not.

    The facets are counted over the *whole* dataset, not over the filtered
    result — a selector whose options disappear as you use it is unusable.
    """
    dataset = _require_dataset(dataset_id)
    matching = evaluation.resolve_items(
        dataset, {"projects": project, "cweIds": cwe, "search": search},
    )
    return {
        "dataset": {"id": dataset.id, "name": dataset.name, "itemCount": len(dataset.items)},
        "items": [item.summary() for item in matching],
        "matched": len(matching),
        "facets": dataset.descriptors(),
    }


@app.post("/api/eval/scope")
async def post_eval_scope(payload: dict) -> dict:
    """Resolves a scope without starting anything — the page's live preview.

    It runs the same code the create endpoint does, so the count shown before
    submitting is the count that will actually be created.
    """
    dataset = _require_dataset(str(payload.get("datasetId") or ""))
    try:
        return evaluation.scope_summary(dataset, _require_scope(payload))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/eval/runs")
async def post_eval_run(payload: dict) -> dict:
    """Resolves a scope into samples and queues them for the audit worker pool."""
    dataset = _require_dataset(str(payload.get("datasetId") or ""))

    try:
        run, samples = evaluation.create_run(dataset, _require_scope(payload))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    for sample in samples:
        _task_queue.put(sample["id"])

    return evaluation.public_run(run)


@app.get("/api/eval/runs")
async def get_eval_runs() -> dict:
    """Every run, newest first, with its progress and metrics."""
    return {"runs": [evaluation.public_run(run) for run in evaluation.runs()]}


@app.get("/api/eval/runs/{run_id}")
async def get_eval_run(run_id: str) -> dict:
    """One run and its samples, with the dataset metadata joined in."""
    run = evaluation.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")

    dataset = evaluation.datasets().get(run.get("datasetId"))
    return {
        **evaluation.public_run(run),
        "samples": [
            evaluation.public_sample(dataset, sample)
            for sample in evaluation.samples_of(run_id)
        ],
    }


@app.post("/api/eval/runs/{run_id}/cancel")
async def post_eval_cancel(run_id: str) -> dict:
    """Drops a run's queued samples. The sample in flight is left to finish."""
    if evaluation.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")

    cancelled = evaluation.cancel_run(run_id)
    evaluation.refresh_run_status(run_id)
    return {"cancelled": cancelled, "run": evaluation.public_run(evaluation.get_run(run_id))}


@app.post("/api/eval/runs/{run_id}/pause")
async def post_eval_pause(run_id: str) -> dict:
    if evaluation.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")
    try:
        run = evaluation.pause_run(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"run": evaluation.public_run(run)}


@app.post("/api/eval/runs/{run_id}/resume")
async def post_eval_resume(run_id: str) -> dict:
    if evaluation.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")
    try:
        pending = evaluation.resume_run(run_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    for sample_id in pending:
        _task_queue.put(sample_id)
    return {"queued": len(pending), "run": evaluation.public_run(evaluation.get_run(run_id))}


def _retry_eval_run(run_id: str, *, cancelled_only: bool = False) -> dict:
    run = evaluation.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")
    if run.get("status") == "paused":
        raise HTTPException(status_code=400, detail="请先继续这次测评，再重跑样例")

    retried = evaluation.retry_samples(run_id, cancelled_only=cancelled_only)
    if not retried:
        detail = "这次测评没有需要重跑的已取消样例" if cancelled_only else "这次测评没有需要重试的样例"
        raise HTTPException(status_code=400, detail=detail)

    # Restore the run status before publishing work to the worker queue. A
    # worker can claim immediately, and claim_sample checks that the run is live.
    evaluation.refresh_run_status(run_id)
    for sample_id in retried:
        _task_queue.put(sample_id)
    return {"retried": len(retried), "run": evaluation.public_run(evaluation.get_run(run_id))}


@app.post("/api/eval/runs/{run_id}/retry")
async def post_eval_retry(run_id: str) -> dict:
    """Re-queues failed or unparsed samples after the run is active again."""
    return _retry_eval_run(run_id)


@app.post("/api/eval/runs/{run_id}/retry-cancelled")
async def post_eval_retry_cancelled(run_id: str) -> dict:
    """Explicitly re-queues cancelled samples, retaining their run and sample ids."""
    return _retry_eval_run(run_id, cancelled_only=True)


@app.delete("/api/eval/runs/{run_id}")
async def delete_eval_run(run_id: str) -> dict:
    """Removes a run — its samples, and its journal records.

    The journal records go too, so a restart does not replay the run the reader
    just removed.
    """
    if not evaluation.drop_run(run_id):
        raise HTTPException(status_code=404, detail=f"未找到测评 {run_id}")
    return {"removed": run_id}


# --------------------------------------------------------------------------- #
# Start-up
#
# Last in the file on purpose: workers resolve job runners by name when they
# take work off the queue. Start them after those runners have been defined.
# --------------------------------------------------------------------------- #


_replay_tasks()
evaluation.replay_runs()
# Import the surviving legacy generations (and snapshots taken before this
# migration) once. Future events go directly into the per-trace archive.
_legacy_trace_paths = [
    *sorted(JOURNAL.parent.glob(f"{JOURNAL.name}.saved-*.jsonl")),
    JOURNAL.parent / f"{JOURNAL.name}.1",
    JOURNAL,
]
_archive.migrate_legacy(_legacy_trace_paths)
_usage_samples.extend(_archive.usage_samples(MAX_USAGE_SAMPLES))
with _worker_condition:
    _ensure_worker_threads(AUDIT_MAX_CONCURRENCY)


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
