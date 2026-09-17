"""Streams LangChain / LangGraph run events to the dashboard's trace viewer.

Wire it into an entry point with two lines:

    from agent_tracing import tracing_callbacks

    result = await agent.ainvoke(payload, config={"callbacks": tracing_callbacks()})

Spans are serialised into batches and POSTed from a daemon thread, so tracing
never blocks the agent and never raises into it — if the dashboard bridge is not
running the events are simply dropped.

Configuration (environment variables):

    AGENT_TRACE_URL        default http://127.0.0.1:8901/api/agent/events
    BRIDGE_PORT            base the default URL on this port instead
    AGENT_TRACE_DISABLED   set to 1 to turn tracing off entirely

This is deliberately separate from LangSmith: the project already forwards to
LangSmith when ``LANGSMITH_API_KEY`` is set, and this module is for the local
dashboard, which works with no account at all. Running both at once is fine.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import urllib.request
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

def _default_url() -> str:
    # Resolved lazily: this module is imported before the entry point calls
    # load_dotenv(), so reading the environment at import time would miss it.
    return f"http://127.0.0.1:{os.getenv('BRIDGE_PORT', '8901')}/api/agent/events"

_FLUSH_TIMEOUT_S = 0.5
_BATCH_SIZE = 32
_POST_TIMEOUT_S = 2.0

# Payloads are for a human to read in a browser, not for replay, so they are
# truncated hard rather than sent whole.
MAX_TEXT = 6000
MAX_ITEMS = 60
MAX_DEPTH = 6


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _truncate(text: str) -> str:
    if len(text) <= MAX_TEXT:
        return text
    return f"{text[:MAX_TEXT]}\n… <已截断，原文 {len(text)} 字符>"


def _jsonable(value: Any, depth: int = 0) -> Any:
    """Best-effort conversion of whatever LangChain hands us into JSON.

    LangChain callbacks receive pydantic models, dataclasses, message objects and
    raw Python objects depending on the component, so this walks the common cases
    and falls back to ``repr`` rather than raising.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return _truncate(value)

    if depth >= MAX_DEPTH:
        return _truncate(repr(value))

    if isinstance(value, bytes):
        return _truncate(repr(value))

    # Message-like objects (BaseMessage and friends) carry type + content.
    content = getattr(value, "content", None)
    if content is not None and hasattr(value, "type"):
        return {
            "type": getattr(value, "type", "message"),
            "name": getattr(value, "name", None),
            "content": _jsonable(content, depth + 1),
        }

    if isinstance(value, dict):
        items = list(value.items())[:MAX_ITEMS]
        return {str(key): _jsonable(item, depth + 1) for key, item in items}

    if isinstance(value, (list, tuple, set)):
        items = list(value)[:MAX_ITEMS]
        result = [_jsonable(item, depth + 1) for item in items]
        if len(value) > MAX_ITEMS:
            result.append(f"… <还有 {len(value) - MAX_ITEMS} 项>")
        return result

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _jsonable(dump(mode="json"), depth + 1)
        except Exception:
            pass

    if is_dataclass(value) and not isinstance(value, type):
        try:
            return _jsonable(asdict(value), depth + 1)
        except Exception:
            pass

    return _truncate(repr(value))


def _run_name(serialized: Any, name_hint: Any, fallback: str) -> str:
    """The best available label for a run.

    LangGraph starts its root run with ``serialized=None`` and passes the name
    as the ``name=`` keyword argument instead, so that hint is checked first —
    without it every graph would show up as the bare run type.
    """
    if name_hint:
        return str(name_hint)

    if isinstance(serialized, dict):
        name = serialized.get("name")
        if name:
            return str(name)
        identifier = serialized.get("id")
        if isinstance(identifier, list) and identifier:
            return str(identifier[-1])

    return fallback


def _model_name(serialized: Any, metadata: Any) -> str | None:
    if isinstance(metadata, dict):
        for key in ("ls_model_name", "model_name", "model"):
            if metadata.get(key):
                return str(metadata[key])

    if isinstance(serialized, dict):
        kwargs = serialized.get("kwargs")
        if isinstance(kwargs, dict):
            for key in ("model", "model_name"):
                if kwargs.get(key):
                    return str(kwargs[key])
    return None


def _normalise_usage(usage: dict[str, Any]) -> dict[str, int | None]:
    """Input/output split plus the cache breakdown, from either wire shape.

    Providers disagree about cache fields — OpenAI reports
    ``prompt_tokens_details.cached_tokens``, LangChain normalises to
    ``input_token_details.cache_read``, and plenty of providers report neither.
    A missing block is carried through as ``None`` rather than 0, so that "this
    provider says nothing about caching" never renders as a 0% hit rate.

    ``inputTokens`` counts every input token *including* the cached ones, which
    is what makes the hit rate a plain ratio of the two.
    """
    raw_details = usage.get("input_token_details")
    raw_prompt_details = usage.get("prompt_tokens_details")
    details = raw_details if isinstance(raw_details, dict) else {}
    prompt_details = raw_prompt_details if isinstance(raw_prompt_details, dict) else {}
    cache_reported = bool(details) or bool(prompt_details)

    def pick(*candidates: Any) -> int:
        for candidate in candidates:
            if isinstance(candidate, (int, float)):
                return int(candidate)
        return 0

    return {
        "inputTokens": pick(usage.get("input_tokens"), usage.get("prompt_tokens")),
        "outputTokens": pick(usage.get("output_tokens"), usage.get("completion_tokens")),
        "totalTokens": pick(usage.get("total_tokens")),
        "cacheReadTokens": pick(details.get("cache_read"), prompt_details.get("cached_tokens")) if cache_reported else None,
        "cacheCreationTokens": pick(details.get("cache_creation"), prompt_details.get("cache_creation_tokens")) if cache_reported else None,
    }


def _token_usage(response: Any) -> dict[str, int] | None:
    """Reads the usage block out of an ``LLMResult``, whichever shape it uses."""
    llm_output = getattr(response, "llm_output", None) or {}
    usage = llm_output.get("token_usage") or llm_output.get("usage")
    if isinstance(usage, dict) and usage:
        return _normalise_usage(usage)

    generations = getattr(response, "generations", None) or []
    for group in generations:
        for generation in group or []:
            message = getattr(generation, "message", None)
            metadata = getattr(message, "usage_metadata", None)
            if isinstance(metadata, dict) and metadata:
                return _normalise_usage(metadata)
    return None


class BridgeTracer(BaseCallbackHandler):
    """Collects spans and ships them to the dashboard in the background."""

    # Every callback only appends to an unbounded queue, so running it inline on
    # the event loop is cheaper than LangChain's default thread-pool hop.
    run_inline = True

    def __init__(self, endpoint: str) -> None:
        super().__init__()
        self._endpoint = endpoint
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._lock = threading.Lock()
        self._roots: dict[UUID, UUID] = {}

        self._thread = threading.Thread(target=self._pump, name="agent-tracer", daemon=True)
        self._thread.start()

    # -- plumbing ------------------------------------------------------------

    def _emit(self, event: dict[str, Any]) -> None:
        self._queue.put(event)

    def _pump(self) -> None:
        while True:
            batch = []
            try:
                batch.append(self._queue.get(timeout=_FLUSH_TIMEOUT_S))
            except queue.Empty:
                continue

            while len(batch) < _BATCH_SIZE:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break

            self._post(batch)

    def _post(self, batch: list[dict[str, Any]]) -> None:
        try:
            body = json.dumps(batch, ensure_ascii=False, default=str).encode("utf-8")
            request = urllib.request.Request(
                self._endpoint,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=_POST_TIMEOUT_S).close()
        except Exception:
            # Tracing is a side channel: a missing bridge must never surface.
            pass

    def _root_of(self, run_id: UUID, parent_run_id: UUID | None) -> UUID:
        with self._lock:
            if parent_run_id is None:
                self._roots[run_id] = run_id
                return run_id
            root = self._roots.get(parent_run_id, parent_run_id)
            self._roots[run_id] = root
            return root

    def _start(
        self,
        kind: str,
        serialized: Any,
        run_id: UUID,
        parent_run_id: UUID | None,
        *,
        name: Any = None,
        inputs: Any = None,
        metadata: Any = None,
        tags: Any = None,
    ) -> None:
        self._emit({
            "type": "span.start",
            "traceId": str(self._root_of(run_id, parent_run_id)),
            "spanId": str(run_id),
            "parentId": str(parent_run_id) if parent_run_id else None,
            "name": _run_name(serialized, name, kind),
            "kind": kind,
            "startedAt": _now(),
            "inputs": _jsonable(inputs),
            "model": _model_name(serialized, metadata),
            "tags": [str(tag) for tag in (tags or [])][:MAX_ITEMS],
        })

    def _end(self, run_id: UUID, outputs: Any = None, usage: Any = None) -> None:
        event: dict[str, Any] = {
            "type": "span.end",
            "spanId": str(run_id),
            "endedAt": _now(),
        }
        if outputs is not None:
            event["outputs"] = _jsonable(outputs)
        if usage:
            event["usage"] = usage

        self._emit(event)

        with self._lock:
            self._roots.pop(run_id, None)

    def _error(self, run_id: UUID, error: BaseException) -> None:
        self._emit({
            "type": "span.error",
            "spanId": str(run_id),
            "endedAt": _now(),
            "error": _truncate(f"{type(error).__name__}: {error}"),
        })

        with self._lock:
            self._roots.pop(run_id, None)

    # -- chains / graphs -----------------------------------------------------

    def on_chain_start(self, serialized, inputs, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        # `name` arrives here rather than in `serialized` — see `_run_name`.
        self._start("chain", serialized, run_id, parent_run_id, name=kwargs.get("name"), inputs=inputs, metadata=metadata, tags=tags)

    def on_chain_end(self, outputs, *, run_id, parent_run_id=None, **kwargs):
        self._end(run_id, outputs=outputs)

    def on_chain_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._error(run_id, error)

    # -- model calls ---------------------------------------------------------

    def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._start("model", serialized, run_id, parent_run_id, inputs=messages, metadata=metadata, tags=tags)

    def on_llm_start(self, serialized, prompts, *, run_id, parent_run_id=None, tags=None, metadata=None, **kwargs):
        self._start("model", serialized, run_id, parent_run_id, inputs=prompts, metadata=metadata, tags=tags)

    def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
        outputs = None
        generations = getattr(response, "generations", None)
        if generations:
            outputs = [
                [getattr(generation, "text", None) or getattr(getattr(generation, "message", None), "content", None)
                 for generation in group or []]
                for group in generations
            ]
        self._end(run_id, outputs=outputs, usage=_token_usage(response))

    def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._error(run_id, error)

    # -- tool calls ----------------------------------------------------------

    def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, tags=None, metadata=None, inputs=None, **kwargs):
        self._start("tool", serialized, run_id, parent_run_id, inputs=inputs if inputs is not None else input_str, metadata=metadata, tags=tags)

    def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
        self._end(run_id, outputs=output)

    def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
        self._error(run_id, error)


_tracers: list[BaseCallbackHandler] | None = None


def tracing_callbacks() -> list[BaseCallbackHandler]:
    """Returns the callback list to pass to ``config={"callbacks": ...}``.

    The tracer is a process-wide singleton so every run of the agent lands in the
    same dashboard session.
    """
    global _tracers

    if os.getenv("AGENT_TRACE_DISABLED") == "1":
        return []

    if _tracers is None:
        _tracers = [BridgeTracer(os.getenv("AGENT_TRACE_URL") or _default_url())]

    return _tracers
