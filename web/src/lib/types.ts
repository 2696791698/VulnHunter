/** State of a check. `idle` means the bridge can run it but has not yet. */
export type CheckState = 'pass' | 'fail' | 'running' | 'idle'

/**
 * Exactly what the bridge sends, and nothing more.
 *
 * Every text field the UI shows for a check — its name, transport label,
 * description, the environment variables it needs, its target and its icon —
 * is produced by the backend. The frontend has no copy of any of it, so it can
 * never show a value the backend did not report.
 */
export interface CheckResult {
  id: string
  name: string
  transport: string
  transportLabel: string
  description: string
  requires: string[]
  /** Icon name resolved through `check-icons.ts`. */
  icon: string
  /** Null when the value it reports is not configured. */
  target: string | null
  state: CheckState
  latencyMs: number | null
  message: string | null
  log: string[]
}

/** When the reading on screen was taken, and how long the whole round took. */
export interface EnvironmentRun {
  startedAt: string
  durationMs: number
}

/** What the bridge reports about the environment: the current reading only. */
export interface EnvironmentReading {
  checks: CheckResult[]
  /** Null before the first run — the cards then read `idle`. */
  lastRun: EnvironmentRun | null
}

/** `unavailable` means the bridge could not be reached at all. */
export type Source = 'live' | 'unavailable'

export interface EnvironmentSnapshot extends EnvironmentReading {
  source: Source
}

/**
 * Token consumption, aggregated by the bridge from the model spans the tracer
 * posted. `inputTokens` counts every input token including the cached ones;
 * `cacheHitRate` is null when the provider reported no input tokens at all.
 */
export interface UsageTotals {
  requests: number
  inputTokens: number
  newInputTokens: number
  outputTokens: number
  /** Null when no span reported cache fields; the UI reads that as 0. */
  cacheReadTokens: number | null
  cacheCreationTokens: number | null
  totalTokens: number
  /** Null when nothing reported caching, or when nothing was sent. */
  cacheHitRate: number | null
}

export interface UsageBucket extends UsageTotals {
  /** The UTC hour, as an ISO string. Formatted in the reader's timezone. */
  key: string
}

export interface UsageInterval {
  value: string
  label: string
}

export interface TokenUsage {
  totals: UsageTotals | null
  /** Distinct model names behind the totals, as reported by the spans. */
  models: string[]
  buckets: UsageBucket[]
  /** The bucket size the series was grouped by, echoed back by the bridge. */
  interval: string
  /** Bucket sizes the bridge offers; the selector renders these verbatim. */
  intervals: UsageInterval[]
}

/** Lifecycle of an audit task: clone, then hand the checkout to the agent. */
export type AuditStatus = 'queued' | 'cloning' | 'running' | 'done' | 'failed'

export interface AuditTask {
  id: string
  url: string
  commit: string
  status: AuditStatus
  createdAt: string
  startedAt: string | null
  endedAt: string | null
  /** Where the checkout landed, or null before the clone finished. */
  checkout: string | null
  /** The agent's final answer, or null until it finishes. */
  verdict: string | null
  error: string | null
}

/** What the bridge reports about itself, for the "copy start command" action. */
export interface BridgeInfo {
  command: string
  python: string
  port: number
  journal: string
}
