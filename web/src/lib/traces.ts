export type SpanKind = 'chain' | 'model' | 'tool'
export type SpanStatus = 'running' | 'ok' | 'error'

export interface SpanUsage {
  inputTokens?: number | null
  outputTokens?: number | null
  totalTokens?: number | null
}

/** Which LangGraph node a span ran in. Null for runs outside a graph. */
export interface SpanGraph {
  step?: number | string | null
  node?: string | null
  key?: string
}

/** Exactly what the bridge stores, as posted by `agent_tracing.py`. */
export interface Span {
  id: string
  traceId: string
  /** null on the root span. */
  parentId: string | null
  name: string
  kind: SpanKind
  startedAt: string
  endedAt: string | null
  status: SpanStatus
  /** Null when the span was fetched without payloads, or released by the
   * bridge's memory budget. */
  inputs: unknown
  outputs: unknown
  error: string | null
  model: string | null
  usage: SpanUsage | null
  tags: string[]
  graph?: SpanGraph | null
  /** True when `parentId` had to be recovered from `graph` rather than read
   * off the run — the trace would have been split in two without it. */
  adopted?: boolean
  sizeBytes?: number
}

export interface TraceSummary {
  id: string
  name: string
  startedAt: string
  endedAt: string | null
  status: SpanStatus
  spanCount: number
  errorCount: number
  usage: SpanUsage | null
  /** Incremented on every accepted event, so the dashboard can tell whether a
   * trace changed without refetching it to find out. */
  revision?: number
  sizeBytes?: number
}

export interface Trace extends TraceSummary {
  spans: Span[]
}

/**
 * Vocabulary for the two enums in the trace protocol. The backend sends the
 * enum values; these are the words the UI renders them as.
 */
export const SPAN_KIND_LABELS: Record<SpanKind, string> = {
  chain: '编排',
  model: '模型调用',
  tool: '工具调用',
}

export const SPAN_STATUS_LABELS: Record<SpanStatus, string> = {
  running: '运行中',
  ok: '成功',
  error: '失败',
}
