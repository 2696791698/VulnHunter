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
export type AuditStatus = 'queued' | 'cloning' | 'running' | 'done' | 'failed' | 'cancelled'

/**
 * What an audit covers. `project` is the whole checkout; `function` is a single
 * function the caller names, which is why it also has to say where that
 * function lives.
 */
export type AuditMode = 'project' | 'function'

export interface AuditEvidenceRef {
  kind: 'file' | 'command' | 'output' | 'url' | 'other'
  ref: string
  quote: string | null
}

export interface VulnerabilityReport {
  summary: string
  affected_location: string
  preconditions: string[]
  steps: string[]
  expected_effect: string
  observed_effect: string | null
  poc: string | null
  verification_status: 'dynamic_confirmed' | 'static_inferred' | 'not_reproduced'
  evidence: AuditEvidenceRef[]
}

/** The model's validated result: numeric verdict plus a conditional report. */
export interface AuditAssessment {
  verdict: 0 | 1
  reproduction_report: VulnerabilityReport | null
}

export interface AuditTask {
  id: string
  url: string
  commit: string
  mode: AuditMode
  /** Repo-relative path of the audited function's file; null in project mode. */
  filePath: string | null
  /** The function's source as submitted; null in project mode. */
  functionCode: string | null
  status: AuditStatus
  createdAt: string
  startedAt: string | null
  endedAt: string | null
  /** Where the checkout landed, or null before cloning or after cleanup. */
  checkout: string | null
  /** The agent's final answer, or null until it finishes. */
  verdict: AuditAssessment | string | null
  error: string | null
}

/**
 * What `POST /api/audit/tasks` accepts, as a union rather than an optional-pair
 * object: a function-level task without its target is not a shape the bridge
 * can do anything with, so it is not a shape that can be built here.
 */
export type AuditSubmission =
  | { url: string, commit: string, mode: 'project' }
  | { url: string, commit: string, mode: 'function', filePath: string, functionCode: string }

/** What the bridge reports about itself, for the "copy start command" action. */
export interface BridgeInfo {
  command: string
  python: string
  port: number
  journal: string
  archive?: string
}

/** The active LLM configuration. Secrets are never returned by the bridge. */
export interface ModelConfiguration {
  provider: string
  modelName: string
  reasoningEffort: string
  baseUrl: string
  apiKeyConfigured: boolean
}

/** Credentials are only sent when the user enters a replacement key. */
export interface SaveModelConfiguration {
  provider: string
  modelName: string
  reasoningEffort: string
  baseUrl: string
  apiKey?: string
  clearApiKey?: boolean
}

/** The maximum number of audit and evaluation jobs the bridge runs at once. */
export interface ConcurrencyConfiguration {
  maxConcurrency: number
}

/* -------------------------------------------------------------------------- */
/* Benchmark evaluation                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Which side of a pair a sample audits. `vul` is the vulnerable function from
 * the parent of the fixing commit; `sec` is the patched function at the commit
 * itself. `both` is a scope choice, not a sample: it means the two sides of each
 * selected pair are queued as two samples.
 */
export type EvalSampleType = 'vul' | 'sec'
export type EvalScopeTypes = EvalSampleType | 'both'
/** Paused runs need an explicit resume, including after a service restart. */
export type EvalRunStatus = 'queued' | 'running' | 'paused' | 'done' | 'interrupted'
/**
 * `cancelled` is separate from `failed`: both are jobs that produced nothing to
 * score, but one was stopped on purpose and the other broke.
 */
export type EvalSampleStatus = 'queued' | 'cloning' | 'running' | 'done' | 'failed' | 'cancelled'
export type EvalPrediction = 'vulnerable' | 'non-vulnerable'

/** One ratio plus the counts behind it, so the UI can show `50% (1/2)`. */
export interface EvalMetric {
  /** Null when the denominator is zero — a rate over nothing is not 0. */
  value: number | null
  numerator: number | null
  denominator: number | null
}

export interface EvalSampleCounts {
  tp: number
  fp: number
  tn: number
  fn: number
}

/**
 * Detection metrics over the samples that produced a measurement.
 *
 * Three outcomes are counted differently, and the split is visible here so the
 * page never has to guess: a sample that answered is scored; one that ran but
 * answered without a parseable verdict is a miss; and one that never ran
 * (`failed` / `cancelled`) is kept out of the matrix. `counted` is the size of
 * the matrix and `excluded` is what was left out.
 */
export interface EvalMetrics {
  total: number
  /** Reached a terminal state: counted + excluded. */
  finished: number
  /** In the confusion matrix — answered, or answered without a verdict. */
  counted: number
  /** Left out of the matrix because nothing was measured. */
  excluded: number
  /** Ran, but the answer carried no parseable verdict. Counted as a miss. */
  unparsed: number
  failed: number
  cancelled: number
  /** Not terminal yet, so not counted either way. */
  pending: number
  confusion: EvalSampleCounts
  pairs: {
    total: number
    correct: number
    vulnerable: number
    nonVulnerable: number
    reversed: number
  }
  /**
   * The ratios sit at this level rather than under a nested `metrics` key: they
   * are the thing the page shows, and the counts above are what they came from.
   */
  recall: EvalMetric
  fpr: EvalMetric
  precision: EvalMetric
  f1: EvalMetric
  accuracy: EvalMetric
  pairCorrectness: EvalMetric
  youdenJ: EvalMetric
}

/**
 * The keys of `EvalMetrics` that hold a ratio — picked out by shape rather than
 * listed, so adding one to the interface is enough for it to be renderable.
 */
export type EvalMetricKey = {
  [K in keyof EvalMetrics]: EvalMetrics[K] extends EvalMetric ? K : never
}[keyof EvalMetrics]

/** A scope choice the dataset offers, with its label produced by the bridge. */
export interface EvalTypeOption {
  value: EvalScopeTypes
  label: string
  detail: string
}

export interface EvalDatasetDescriptor {
  id: string
  name: string
  description: string
  itemCount: number
  typeOptions: EvalTypeOption[]
}

/** One vulnerability–fix pair, without its two function bodies. */
export interface EvalItem {
  id: string
  projectName: string
  cveIds: string[]
  cweIds: string[]
  filePath: string
  repoUrl: string
  commit: string
  language: string
  commitMessage: string
  vulnerableChars: number
  patchedChars: number
}

export interface EvalFacet {
  value: string
  count: number
}

/**
 * The filters that narrow a dataset listing. The same shape the scope carries,
 * so the rows on screen and the scope they would resolve to are built from one
 * object rather than two that have to be kept in step.
 */
export interface EvalFilters {
  search?: string
  projects?: string[]
  cweIds?: string[]
}

export interface EvalDatasetItems {
  dataset: { id: string, name: string, itemCount: number }
  /** The matching pairs. Shorter than `itemCount` whenever a filter is on. */
  items: EvalItem[]
  matched: number
  /** Counted over the whole dataset, so the selector's options never vanish. */
  facets: {
    typeOptions: EvalTypeOption[]
    projects: EvalFacet[]
    cweIds: EvalFacet[]
  }
}

/**
 * What to evaluate. An explicit `itemIds` wins over the filters — it is what the
 * page sends once rows have been ticked by hand.
 */
export interface EvalScope {
  itemIds?: string[]
  projects?: string[]
  cweIds?: string[]
  search?: string
  types?: EvalScopeTypes
}

/** What a scope resolves to. The bridge computes it; the page renders it. */
export interface EvalScopeSummary {
  itemCount: number
  sampleCount: number
  types: EvalScopeTypes
  title: string
  projects: EvalFacet[]
}

export interface EvalProgress {
  queued: number
  cloning: number
  running: number
  done: number
  failed: number
  cancelled: number
  total: number
  /** `done` + `failed` + `cancelled`: how many samples are past running. */
  finished: number
}

export interface EvalRun {
  id: string
  datasetId: string
  datasetName: string
  title: string
  types: EvalScopeTypes
  scope: EvalScope
  status: EvalRunStatus
  createdAt: string
  startedAt: string | null
  endedAt: string | null
  pausedAt: string | null
  pausedReason: 'manual' | 'restart' | null
  /**
   * When the user last resumed a paused run, and how many pending samples were
   * queued. Null on a run that has never been resumed.
   */
  resumedAt: string | null
  resumedSamples: number | null
  error: string | null
  sampleCount: number
  progress: EvalProgress
  metrics: EvalMetrics
}

export interface EvalSample {
  id: string
  runId: string
  itemId: string
  type: EvalSampleType
  status: EvalSampleStatus
  /** The label the dataset gives this sample. */
  truth: EvalPrediction
  /** What the agent said, or null when it produced no parseable verdict. */
  prediction: EvalPrediction | null
  /** Null when there is no prediction to compare — not a `false`. */
  correct: boolean | null
  verdict: AuditAssessment | string | null
  error: string | null
  checkout: string | null
  startedAt: string | null
  endedAt: string | null
  projectName: string | null
  filePath: string | null
  cveIds: string[]
  cweIds: string[]
  commit: string | null
}

export interface EvalRunDetail extends EvalRun {
  samples: EvalSample[]
}

/** What the bridge sends when a run is created or its state is changed. */
export interface EvalRunPatch {
  run: EvalRun
}
