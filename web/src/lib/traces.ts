export type SpanKind = 'chain' | 'model' | 'tool'
export type SpanStatus = 'running' | 'ok' | 'error' | 'interrupted'
export type TraceStatus = SpanStatus | 'cancelled'

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
  /** True when this span only carries a descendant's exception upward: the
   * failure belongs to the span below it, and this one merely reports it again
   * on the way out. False for spans that never errored. */
  propagated: boolean
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
  status: TraceStatus
  canStop: boolean
  stopRequested: boolean
  spanCount: number
  /** Distinct failures. An exception crossing several nested spans is still one:
   * the bridge counts a span only when no ancestor carries the same error. */
  errorCount: number
  usage: SpanUsage | null
  /** Incremented on every accepted event, so the dashboard can tell whether a
   * trace changed without refetching it to find out. */
  revision?: number
  sizeBytes?: number
  /** The surviving legacy events did not include the root span. */
  partial?: boolean
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

export const SPAN_STATUS_LABELS: Record<TraceStatus, string> = {
  running: '运行中',
  ok: '成功',
  error: '失败',
  interrupted: '已中断',
  cancelled: '已停止',
}
