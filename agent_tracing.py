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
import logging
import os
import queue
import threading
import time
import urllib.request
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

logger = logging.getLogger(__name__)

def _default_url() -> str:
    # Resolved lazily: this module is imported before the entry point calls
    # load_dotenv(), so reading the environment at import time would miss it.
    return f"http://127.0.0.1:{os.getenv('BRIDGE_PORT', '8901')}/api/agent/events"

_FLUSH_TIMEOUT_S = 0.5
_BATCH_SIZE = 32
# A batch is bounded by bytes as well as by count: one audit can now carry
# multi-megabyte payloads, and 32 of those is not something to send in one go.
_BATCH_BYTES = int(os.getenv("AGENT_TRACE_BATCH_BYTES", str(8 * 1024 * 1024)))
_POST_TIMEOUT_S = float(os.getenv("AGENT_TRACE_POST_TIMEOUT_S", "60"))
_POST_ATTEMPTS = 3
_POST_BACKOFF_S = (0.25, 1.0, 2.0)
# Bounded so a bridge that stops draining cannot grow the queue without limit.
# `_emit` uses `put_nowait`, so a full queue drops events rather than stalling
# the agent's event loop (this handler runs inline - see `run_inline`).
_QUEUE_MAX = int(os.getenv("AGENT_TRACE_QUEUE_MAX", "8192"))
_MAX_TAGS = 1000
# Ceiling on the run-id bookkeeping. Large enough that every run of an audit
# stays resolvable, small enough that a process running audits for days cannot
# grow it without limit.
_RUNS_MAX = int(os.getenv("AGENT_TRACE_RUNS_MAX", "50000"))
# Guard against unbounded recursion on a self-referential payload. This is a
# crash guard, not a truncation: the flat cases below are all preserved whole.
_SAFE_DEPTH = 300

# Payloads are sent whole. There is no text/item/depth cap any more.


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _approx_bytes(value: Any, depth: int = 0) -> int:
    """Cheap size estimate, so the bridge can budget memory per trace.

    Deliberately not ``json.dumps``: serialising every event twice to measure it
    would cost more than the measurement is worth.
    """
    if depth > 32:
        return 0
    if value is None or isinstance(value, (bool, int, float)):
        return 8
    if isinstance(value, str):
        return len(value)
    if isinstance(value, bytes):
        return len(value)
    if isinstance(value, dict):
        return sum(len(str(k)) + _approx_bytes(v, depth + 1) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(_approx_bytes(item, depth + 1) for item in value)
    return len(repr(value))


def _jsonable(value: Any, depth: int = 0, seen: set[int] | None = None) -> Any:
    """Best-effort conversion of whatever LangChain hands us into JSON.

    LangChain callbacks receive pydantic models, dataclasses, message objects and
    raw Python objects depending on the component, so this walks the common cases
    and falls back to ``repr`` rather than raising. Payloads are kept whole; the
    only structure the walk refuses is a cycle, which cannot be represented.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value

    if isinstance(value, str):
        return value

    if isinstance(value, bytes):
        return repr(value)

    if depth >= _SAFE_DEPTH:
        # Only ever reached by pathologically deep data: document the cut rather
        # than let the callback die on a RecursionError and lose the span.
        return f"<嵌套超过 {_SAFE_DEPTH} 层，此处折叠: {type(value).__name__}>"

    if seen is None:
        seen = set()

    # Message-like objects (BaseMessage and friends) carry type + content.
    content = getattr(value, "content", None)
    if content is not None and hasattr(value, "type"):
        message = {
            "type": getattr(value, "type", "message"),
            "name": getattr(value, "name", None),
            "content": _jsonable(content, depth + 1, seen),
        }
        # `content` alone is the prose; these carry the decisions and the
        # accounting. Without them a trace shows what the model said but not
        # what it chose to do, which is most of what an audit trace is for.
        for attr in (
            "tool_calls",
            "invalid_tool_calls",
            "tool_call_id",
            "artifact",
            "usage_metadata",
            "response_metadata",
            "additional_kwargs",
        ):
            extra = getattr(value, attr, None)
            if extra:
                message[attr] = _jsonable(extra, depth + 1, seen)
        return message

    if isinstance(value, dict):
        if id(value) in seen:
            return "<循环引用>"
        seen = seen | {id(value)}
        return {str(key): _jsonable(item, depth + 1, seen) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        if id(value) in seen:
            return "<循环引用>"
        seen = seen | {id(value)}
        return [_jsonable(item, depth + 1, seen) for item in value]

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return _jsonable(dump(mode="json"), depth + 1, seen)
        except Exception:
            pass

    if is_dataclass(value) and not isinstance(value, type):
        try:
            return _jsonable(asdict(value), depth + 1, seen)
        except Exception:
            pass

    return repr(value)


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
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=_QUEUE_MAX)
        self._lock = threading.Lock()
        # run id -> trace root. Entries survive the run ending: a child can be
        # reported after its parent finished, and dropping the mapping then
        # would make that child look like the start of a new trace.
        self._roots: dict[UUID, UUID] = {}
        # graph key -> the chain run for that node. See `_resolve_parent`.
        self._chain_by_key: dict[str, UUID] = {}
        self._dropped = 0
        self._last_drop_log = 0.0

        self._thread = threading.Thread(target=self._pump, name="agent-tracer", daemon=True)
        self._thread.start()

    def stats(self) -> dict[str, int]:
        """Events still queued and events lost — asserted by the verification harness."""
        return {"queued": self._queue.qsize(), "dropped": self._dropped}

    # -- plumbing ------------------------------------------------------------

    def _emit(self, event: dict[str, Any]) -> None:
        # `put_nowait`, never `put`: with `run_inline` this runs on the agent's
        # event loop, so blocking here would stall the agent. Dropping is the
        # lesser evil, and `stats()` surfaces it instead of hiding it.
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped += 1

    def _pump(self) -> None:
        while True:
            batch: list[dict[str, Any]] = []
            size = 0
            try:
                item = self._queue.get(timeout=_FLUSH_TIMEOUT_S)
            except queue.Empty:
                continue
            batch.append(item)
            size += _approx_bytes(item)

            while len(batch) < _BATCH_SIZE:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                batch.append(item)
                size += _approx_bytes(item)
                if size >= _BATCH_BYTES:
                    break

            self._post(batch)

    def _post(self, batch: list[dict[str, Any]]) -> None:
        body = json.dumps(batch, ensure_ascii=False, default=str).encode("utf-8")

        for attempt in range(_POST_ATTEMPTS):
            try:
                request = urllib.request.Request(
                    self._endpoint,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(request, timeout=_POST_TIMEOUT_S).close()
                return
            except Exception:
                if attempt == _POST_ATTEMPTS - 1:
                    break
                time.sleep(_POST_BACKOFF_S[attempt])

        # Tracing is a side channel: a bridge that is down must not break the
        # audit. But the loss is counted rather than vanishing, and logged at
        # most once a minute so a stopped bridge cannot spam the audit log.
        self._dropped += len(batch)
        now = time.monotonic()
        if now - self._last_drop_log > 60:
            self._last_drop_log = now
            logger.warning(
                "桥接服务未接收 %d 条追踪事件 (%s)", len(batch), self._endpoint,
            )

    def _graph_key(self, metadata: Any) -> dict[str, Any] | None:
        """The LangGraph node a run belongs to, or None outside a graph.

        LangGraph stamps every run - node runs *and* the tool/model leaves
        inside them - with `langgraph_step` and `langgraph_checkpoint_ns`. The
        pair identifies the node run exactly, including one node run per
        parallel tool call. It is the only thing that ties a leaf back to its
        node when the run in between is one nobody ever tells us about.
        """
        if not isinstance(metadata, dict):
            return None
        ns = metadata.get("langgraph_checkpoint_ns")
        if not ns:
            return None
        step = metadata.get("langgraph_step")
        return {
            "step": step,
            "node": metadata.get("langgraph_node"),
            # json.dumps, not str(): `step` can be an int or a tuple, and the
            # value has to survive a round trip through the journal unchanged.
            "key": json.dumps([step, str(ns)]),
        }

    def _resolve_parent(
        self,
        parent_run_id: UUID | None,
        graph: dict[str, Any] | None,
    ) -> UUID | None:
        """The run this span should hang under.

        `parent_run_id` is normally the answer. With LangSmith tracing on,
        langchain wraps every middleware hook in `langsmith.traceable(...)`
        (langchain/agents/factory.py), which creates a RunTree sitting between
        the node and the tool/model call. That RunTree is never reported to us,
        yet the inner run names it as its parent - so the id is unknown here and
        the tree fragments. The same run is still stamped with its node's
        `langgraph_*` metadata, so the node can be recovered from that.
        """
        if parent_run_id is None:
            return None
        with self._lock:
            if parent_run_id in self._roots:
                return parent_run_id
        if graph is None:
            return parent_run_id
        with self._lock:
            node = self._chain_by_key.get(graph["key"])
        # Falling back to the unknown id keeps today's behaviour: the span shows
        # up orphaned rather than being attached somewhere wrong.
        return node if node is not None else parent_run_id

    def _root_of(self, run_id: UUID, parent_run_id: UUID | None) -> UUID:
        with self._lock:
            if parent_run_id is None:
                root = run_id
            else:
                root = self._roots.get(parent_run_id, parent_run_id)
            self._roots[run_id] = root
            while len(self._roots) > _RUNS_MAX:
                del self._roots[next(iter(self._roots))]
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
        graph = self._graph_key(metadata)
        parent = self._resolve_parent(parent_run_id, graph)

        if graph is not None and kind == "chain":
            # Only node runs are adoption targets. A leaf that cannot find its
            # node stays visibly orphaned rather than being attached on a guess.
            with self._lock:
                self._chain_by_key[graph["key"]] = run_id
                while len(self._chain_by_key) > _RUNS_MAX:
                    del self._chain_by_key[next(iter(self._chain_by_key))]

        payload = _jsonable(inputs)
        self._emit({
            "type": "span.start",
            "traceId": str(self._root_of(run_id, parent)),
            "spanId": str(run_id),
            "parentId": str(parent) if parent else None,
            "name": _run_name(serialized, name, kind),
            "kind": kind,
            "startedAt": _now(),
            "inputs": payload,
            "model": _model_name(serialized, metadata),
            "tags": [str(tag) for tag in (tags or [])][:_MAX_TAGS],
            "graph": graph,
            # True when `parentId` had to be recovered from the graph metadata
            # because the reported parent was never announced to us.
            "adopted": parent is not None and parent != parent_run_id,
            "sizeBytes": _approx_bytes(payload),
        })

    def _end(self, run_id: UUID, outputs: Any = None, usage: Any = None) -> None:
        event: dict[str, Any] = {
            "type": "span.end",
            "spanId": str(run_id),
            "endedAt": _now(),
        }
        if outputs is not None:
            payload = _jsonable(outputs)
            event["outputs"] = payload
            event["sizeBytes"] = _approx_bytes(payload)
        if usage:
            event["usage"] = usage

        self._emit(event)
        # No `self._roots.pop(run_id)` here on purpose: a child reported after
        # its parent has finished still needs the mapping to find its root.

    def _error(self, run_id: UUID, error: BaseException) -> None:
        self._emit({
            "type": "span.error",
            "spanId": str(run_id),
            "endedAt": _now(),
            "error": f"{type(error).__name__}: {error}",
        })

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
        generations = getattr(response, "generations", None)
        outputs = None
        if generations:
            # The whole message, not just `generation.text`: the text drops the
            # tool calls, which are the agent's actual output. A plain (non-chat)
            # LLM has no message, so its text is used directly.
            outputs = [
                [
                    _jsonable(message) if (message := getattr(generation, "message", None)) is not None
                    else getattr(generation, "text", None)
                    for generation in group or []
                ]
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
