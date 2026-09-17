export type SpanKind = 'chain' | 'model' | 'tool'
export type SpanStatus = 'running' | 'ok' | 'error'

export interface SpanUsage {
  inputTokens?: number | null
  outputTokens?: number | null
  totalTokens?: number | null
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
  inputs: unknown
  outputs: unknown
  error: string | null
  model: string | null
  usage: SpanUsage | null
  tags: string[]
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
