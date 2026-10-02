"""Durable, per-trace event archive for the dashboard.

The bridge's span store is a bounded cache. This archive owns the complete
history: a small append-only index serves the list, and a selected trace is
reconstructed from its own JSONL file. Neither cache eviction nor a bridge
restart deletes archived events.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path


_TRACE_FILE = re.compile(r"^[0-9a-f]{64}\.jsonl$")
_SUMMARY_VERSION = 2


def _append_lines(path: Path, lines: list[str]) -> None:
    """Separate a killed writer's partial final record before appending."""
    if not lines:
        return
    with path.open("ab+") as handle:
        handle.seek(0, 2)
        if handle.tell():
            handle.seek(-1, 2)
            if handle.read(1) != b"\n":
                handle.write(b"\n")
        handle.write("".join(lines).encode("utf-8"))
        handle.flush()


def explicit_tool_failure(outputs: object, fallback_name: str = "tool") -> str | None:
    """Return a failure only for an explicit error ToolMessage or success=false payload."""
    if not isinstance(outputs, dict) or outputs.get("type") != "tool":
        return None

    name = outputs.get("name") or fallback_name
    content = outputs.get("content")
    content_text = ""
    if isinstance(content, str):
        content_text = content
    elif isinstance(content, list):
        content_text = " ".join(
            item.get("text", "") for item in content
            if isinstance(item, dict) and isinstance(item.get("text"), str)
        )

    if outputs.get("status") == "error":
        detail = content_text.strip() or "ToolMessage status=error"
        return f"{name}: {detail[:500]}"

    candidates: list[object] = []
    structured = outputs.get("structured_content") or outputs.get("structuredContent")
    if structured is not None:
        candidates.append(structured)
    artifact = outputs.get("artifact")
    if isinstance(artifact, dict):
        candidates.extend((artifact.get("structured_content"), artifact.get("structuredContent")))
    if content_text:
        try:
            decoded = json.loads(content_text)
        except (json.JSONDecodeError, TypeError):
            decoded = None
        if decoded is not None:
            candidates.append(decoded)

    for candidate in candidates:
        if not isinstance(candidate, dict) or candidate.get("success") is not False:
            continue
        error = candidate.get("error") or candidate.get("message")
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message") or error.get("detail")
            error = f"{code}: {message}" if code and message else (message or code)
        detail = str(error).strip() if error is not None else "tool returned success=false"
        return f"{name}: {detail[:500]}"
    return None


def _apply_metadata(spans: OrderedDict[str, dict], event: dict) -> bool:
    """Update small span metadata, returning false for a duplicate/orphan."""
    span_id = event.get("spanId")
    if not span_id:
        return False
    kind = event.get("type")
    if kind == "span.start":
        if span_id in spans:
            return False
        spans[span_id] = {
            "id": span_id,
            "traceId": event.get("traceId") or span_id,
            "parentId": event.get("parentId"),
            "name": event.get("name") or event.get("kind") or "span",
            "kind": event.get("kind") or "chain",
            "startedAt": event.get("startedAt"),
            "endedAt": None,
            "status": "running",
            "error": None,
            "model": event.get("model"),
            "usage": None,
            "tags": event.get("tags") or [],
            "graph": event.get("graph"),
            "adopted": bool(event.get("adopted")),
            "sizeBytes": int(event.get("sizeBytes") or 0),
        }
        return True
    span = spans.get(span_id)
    if span is None or span["status"] != "running":
        return False
    if kind == "span.end":
        span["endedAt"] = event.get("endedAt")
        failure = (
            explicit_tool_failure(event.get("outputs"), span["name"])
            if span["kind"] == "tool"
            else None
        )
        span["status"] = "error" if failure else "ok"
        span["error"] = failure
        span["sizeBytes"] += int(event.get("sizeBytes") or 0)
        if event.get("usage"):
            span["usage"] = event["usage"]
        return True
    if kind == "span.error":
        span["endedAt"] = event.get("endedAt")
        span["status"] = "error"
        span["error"] = event.get("error")
        return True
    return False


def _failure_count(spans: list[dict]) -> int:
    by_id = {span["id"]: span for span in spans}
    propagated: set[str] = set()
    for span in spans:
        if span["status"] != "error":
            continue
        ancestor_id = span.get("parentId")
        while ancestor_id:
            ancestor = by_id.get(ancestor_id)
            if ancestor is None:
                break
            if ancestor["status"] == "error" and ancestor.get("error") == span.get("error"):
                propagated.add(ancestor_id)
            ancestor_id = ancestor.get("parentId")
    return sum(span["status"] == "error" and span["id"] not in propagated for span in spans)


def _summary(trace_id: str, spans: OrderedDict[str, dict], archive_bytes: int) -> dict | None:
    if not spans:
        return None
    values = list(spans.values())
    root = next((span for span in values if span["parentId"] is None), values[0])
    starts = [span["startedAt"] for span in values if span["startedAt"]]
    ends = [span["endedAt"] for span in values if span["endedAt"]]
    usage = {"inputTokens": 0, "outputTokens": 0, "totalTokens": 0}
    for span in values:
        for key in usage:
            usage[key] += (span.get("usage") or {}).get(key) or 0
    errors = _failure_count(values)
    running = any(span["status"] == "running" for span in values)
    job_id = next(
        (tag.removeprefix("bridge-job:") for tag in root.get("tags", [])
         if isinstance(tag, str) and tag.startswith("bridge-job:")),
        None,
    )
    return {
        "id": trace_id,
        "name": root["name"],
        "startedAt": min(starts) if starts else root["startedAt"],
        "endedAt": None if running else (max(ends) if ends else None),
        "status": "running" if running else ("error" if errors else "ok"),
        "canStop": False,
        "stopRequested": False,
        "spanCount": len(values),
        "errorCount": errors,
        "usage": usage if usage["totalTokens"] else None,
        "revision": sum(1 if s["status"] == "running" else 2 for s in values),
        "sizeBytes": sum(s.get("sizeBytes") or 0 for s in values),
        "partial": all(s["parentId"] is not None for s in values),
        "_jobId": job_id,
        "_archiveBytes": archive_bytes,
        "_summaryVersion": _SUMMARY_VERSION,
    }


class TraceArchive:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.index = root / "index.jsonl"
        self.imports = root / "imports.jsonl"
        self.usage = root / "usage.jsonl"
        self._lock = threading.RLock()
        self.summaries: dict[str, dict] = {}
        self._metadata: dict[str, OrderedDict[str, dict]] = {}
        self._span_to_trace: dict[str, str] = {}
        self._imported: set[tuple[str, int]] = set()
        self._load_index()
        self._load_imports()
        self._recover_index()

    def _path(self, trace_id: str) -> Path:
        return self.root / f"{hashlib.sha256(trace_id.encode('utf-8')).hexdigest()}.jsonl"

    def _load_index(self) -> None:
        if not self.index.exists():
            return
        with self.index.open("rb") as handle:
            for raw in handle:
                try:
                    summary = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(summary, dict) and isinstance(summary.get("id"), str):
                    self.summaries[summary["id"]] = summary

    def _load_imports(self) -> None:
        if not self.imports.exists():
            return
        with self.imports.open("rb") as handle:
            for raw in handle:
                try:
                    record = json.loads(raw)
                    self._imported.add((record["path"], record["size"]))
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
                    continue

    def _load_metadata(self, trace_id: str) -> OrderedDict[str, dict]:
        existing = self._metadata.get(trace_id)
        if existing is not None:
            return existing
        spans: OrderedDict[str, dict] = OrderedDict()
        path = self._path(trace_id)
        if path.exists():
            with path.open("rb") as handle:
                for raw in handle:
                    try:
                        event = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    if _apply_metadata(spans, event) and event.get("type") == "span.start":
                        self._span_to_trace[event["spanId"]] = trace_id
        self._metadata[trace_id] = spans
        return spans

    def _write_summaries(self, trace_ids: set[str]) -> None:
        records = []
        for trace_id in trace_ids:
            path = self._path(trace_id)
            summary = _summary(trace_id, self._load_metadata(trace_id), path.stat().st_size)
            if summary is not None:
                records.append(summary)
        if not records:
            return
        _append_lines(self.index, [json.dumps(record, ensure_ascii=False) + "\n" for record in records])
        self.summaries.update({record["id"]: record for record in records})

    def _recover_index(self) -> None:
        """Repair an index left behind by a crash after the raw event write."""
        stale: set[str] = set()
        known_paths = {self._path(trace_id): trace_id for trace_id in self.summaries}
        for path in self.root.glob("*.jsonl"):
            if not _TRACE_FILE.fullmatch(path.name):
                continue
            trace_id = known_paths.get(path)
            if trace_id is None:
                with path.open("rb") as handle:
                    for raw in handle:
                        try:
                            event = json.loads(raw)
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        trace_id = event.get("traceId")
                        if trace_id:
                            break
            if trace_id:
                summary = self.summaries.get(trace_id, {})
                if (
                    path.stat().st_size != summary.get("_archiveBytes")
                    or summary.get("_summaryVersion") != _SUMMARY_VERSION
                ):
                    stale.add(trace_id)
        if stale:
            self._write_summaries(stale)
        for trace_id, spans in list(self._metadata.items()):
            if self.summaries.get(trace_id, {}).get("status") != "running":
                for span_id in spans:
                    self._span_to_trace.pop(span_id, None)
                self._metadata.pop(trace_id, None)
        for trace_id, summary in self.summaries.items():
            if summary.get("status") == "running":
                self._load_metadata(trace_id)

    def append(self, events: list[dict], *, prune_completed: bool = True) -> list[dict]:
        """Persist new events before acknowledgement; duplicate POSTs are safe."""
        with self._lock:
            accepted: list[dict] = []
            by_trace: dict[str, list[str]] = {}
            touched: set[str] = set()
            observed: set[str] = set()
            usage_records: list[dict] = []
            try:
                for event in events:
                    if not isinstance(event, dict) or not event.get("spanId"):
                        continue
                    span_id = event["spanId"]
                    trace_id = (event.get("traceId") if event.get("type") == "span.start"
                                else self._span_to_trace.get(span_id) or event.get("traceId"))
                    if event.get("type") == "span.start":
                        trace_id = trace_id or span_id
                        self._span_to_trace[span_id] = trace_id
                    if not isinstance(trace_id, str) or not trace_id:
                        continue
                    observed.add(trace_id)
                    spans = self._load_metadata(trace_id)
                    if not _apply_metadata(spans, event):
                        continue
                    normalized = {**event, "traceId": trace_id}
                    by_trace.setdefault(trace_id, []).append(json.dumps(normalized, ensure_ascii=False, default=str) + "\n")
                    accepted.append(normalized)
                    touched.add(trace_id)
                    if event.get("type") == "span.end" and event.get("usage"):
                        span = spans[span_id]
                        if span.get("kind") == "model" and (span["usage"] or {}).get("totalTokens"):
                            usage_records.append({"startedAt": span["startedAt"], "model": span["model"], "usage": span["usage"]})
                for trace_id, lines in by_trace.items():
                    _append_lines(self._path(trace_id), lines)
                # A previous POST can have written raw events and then failed
                # while writing the index. Its retry is all duplicates, but it
                # must still repair that stale index before acknowledgement.
                stale = {trace_id for trace_id in observed
                         if self._path(trace_id).exists()
                         and self._path(trace_id).stat().st_size
                         != self.summaries.get(trace_id, {}).get("_archiveBytes")}
                self._write_summaries(touched | stale)
                if usage_records:
                    _append_lines(self.usage, [json.dumps(record, ensure_ascii=False) + "\n" for record in usage_records])
            except OSError:
                for trace_id in touched:
                    self._metadata.pop(trace_id, None)
                raise
            if prune_completed:
                for trace_id in touched:
                    spans = self._metadata.get(trace_id)
                    if spans and all(span["status"] != "running" for span in spans.values()):
                        for span_id in spans:
                            self._span_to_trace.pop(span_id, None)
                        del self._metadata[trace_id]
            return accepted

    def list_summaries(self) -> list[dict]:
        with self._lock:
            return sorted((dict(value) for value in self.summaries.values()),
                          key=lambda item: item.get("startedAt") or "", reverse=True)

    def get_summary(self, trace_id: str) -> dict | None:
        with self._lock:
            summary = self.summaries.get(trace_id)
            return dict(summary) if summary else None

    def last_activity_at(self, trace_id: str) -> str | None:
        """Last observed span timestamp, even if a killed run has no end event."""
        with self._lock:
            latest: tuple[datetime, str] | None = None
            for span in self._load_metadata(trace_id).values():
                for raw in (span.get("startedAt"), span.get("endedAt")):
                    if not isinstance(raw, str):
                        continue
                    try:
                        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if moment.tzinfo is None:
                        moment = moment.replace(tzinfo=timezone.utc)
                    if latest is None or moment > latest[0]:
                        latest = (moment, raw)
            return latest[1] if latest else None

    def read_trace(self, trace_id: str, payloads: bool) -> list[dict] | None:
        with self._lock:
            if trace_id not in self.summaries:
                return None
            path = self._path(trace_id)
            spans: OrderedDict[str, dict] = OrderedDict()
            with path.open("rb") as handle:
                for raw in handle:
                    try:
                        event = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if not isinstance(event, dict):
                        continue
                    span_id = event.get("spanId")
                    kind = event.get("type")
                    if kind == "span.start" and span_id and span_id not in spans:
                        spans[span_id] = {
                            "id": span_id, "traceId": trace_id,
                            "parentId": event.get("parentId"),
                            "name": event.get("name") or event.get("kind") or "span",
                            "kind": event.get("kind") or "chain",
                            "startedAt": event.get("startedAt"), "endedAt": None,
                            "status": "running",
                            "inputs": event.get("inputs") if payloads else None,
                            "outputs": None, "error": None,
                            "model": event.get("model"), "usage": None,
                            "tags": event.get("tags") or [],
                            "graph": event.get("graph"),
                            "adopted": bool(event.get("adopted")),
                            "sizeBytes": int(event.get("sizeBytes") or 0),
                        }
                    elif kind in {"span.end", "span.error"} and span_id in spans and spans[span_id]["status"] == "running":
                        span = spans[span_id]
                        span["endedAt"] = event.get("endedAt")
                        if kind == "span.end":
                            failure = (
                                explicit_tool_failure(event.get("outputs"), span["name"])
                                if span["kind"] == "tool"
                                else None
                            )
                            span["status"] = "error" if failure else "ok"
                            span["error"] = failure
                            span["outputs"] = event.get("outputs") if payloads else None
                            span["usage"] = event.get("usage")
                            span["sizeBytes"] += int(event.get("sizeBytes") or 0)
                        else:
                            span["status"] = "error"
                            span["error"] = event.get("error")
            return list(spans.values())

    def usage_samples(self, limit: int) -> list[dict]:
        if not self.usage.exists():
            return []
        samples = []
        with self.usage.open("rb") as handle:
            for raw in handle:
                try:
                    samples.append(json.loads(raw))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                del samples[:-limit]
        return samples

    def migrate_legacy(self, paths: list[Path]) -> dict:
        """Import surviving rotated logs once, including point-in-time copies."""
        imported = 0
        skipped = 0
        for path in paths:
            if not path.exists():
                continue
            size = path.stat().st_size
            marker = (str(path.resolve()), size)
            if marker in self._imported:
                continue
            batch: list[dict] = []
            with path.open("rb") as handle:
                for raw in handle:
                    try:
                        event = json.loads(raw)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        skipped += 1
                        continue
                    if isinstance(event, dict):
                        batch.append(event)
                    if len(batch) >= 32:
                        imported += len(self.append(batch, prune_completed=False))
                        batch.clear()
                if batch:
                    imported += len(self.append(batch, prune_completed=False))
            _append_lines(self.imports, [json.dumps({"path": marker[0], "size": marker[1]}, ensure_ascii=False) + "\n"])
            self._imported.add(marker)
        for trace_id, spans in list(self._metadata.items()):
            if spans and all(span["status"] != "running" for span in spans.values()):
                for span_id in spans:
                    self._span_to_trace.pop(span_id, None)
                del self._metadata[trace_id]
        return {"imported": imported, "damaged": skipped}

    def clear(self) -> list[str]:
        with self._lock:
            removed = []
            for path in self.root.glob("*.jsonl"):
                if path not in {self.index, self.imports, self.usage} and not _TRACE_FILE.fullmatch(path.name):
                    continue
                path.unlink(missing_ok=True)
                removed.append(str(path))
            self.summaries.clear()
            self._metadata.clear()
            self._span_to_trace.clear()
            self._imported.clear()
            return removed
