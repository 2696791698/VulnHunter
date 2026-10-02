import type { Span, Trace, TraceSummary } from './traces'
import type {
  AuditSubmission,
  AuditTask,
  BridgeInfo,
  ConcurrencyConfiguration,
  EnvironmentReading,
  EvalDatasetDescriptor,
  EvalDatasetItems,
  EvalFilters,
  EvalRun,
  EvalRunDetail,
  EvalScope,
  EvalScopeSummary,
  ModelConfiguration,
  SaveModelConfiguration,
  TokenUsage,
} from './types'

/**
 * Base URL of the optional Python bridge in `server/`. It is proxied by Vite in
 * development (see `vite.config.ts`), so the default works out of the box.
 */
const API_BASE = import.meta.env.VITE_API_BASE ?? '/api'

/** The bridge may not be running — keep the probe short so the UI can say so. */
const PROBE_TIMEOUT_MS = 2500
const RUN_TIMEOUT_MS = 180_000
/** Payloads are stored whole and a single span can be megabytes, so this is
 * sized for a large body over a devcontainer port-forward, not for a probe. */
const PAYLOAD_TIMEOUT_MS = 120_000

/** The bridge answered, but with an error of its own (as opposed to not being
 * reachable at all, which surfaces as a plain `Error`). */
export class BridgeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BridgeError'
  }
}

/** FastAPI puts a human-readable reason in `detail`; Vite's proxy error page
 * does not, which is how the two failure modes are told apart. */
async function readDetail(response: Response): Promise<string | null> {
  try {
    const body = await response.json() as { detail?: unknown }
    return typeof body.detail === 'string' ? body.detail : null
  }
  catch {
    return null
  }
}

async function request<T>(path: string, { timeoutMs = PROBE_TIMEOUT_MS, ...init }: RequestInit & { timeoutMs?: number } = {}): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal })

    if (!response.ok) {
      const detail = await readDetail(response)
      throw detail
        ? new BridgeError(detail)
        : new Error(`${response.status} ${response.statusText}`)
    }

    return await response.json() as T
  }
  finally {
    clearTimeout(timer)
  }
}

/** The checks the bridge knows about, and when the current reading was taken. */
export function fetchSnapshot(): Promise<EnvironmentReading> {
  return request<EnvironmentReading>('/environment')
}

/** Runs all five checks for real and replaces the reading; can take a minute. */
export function runChecks(): Promise<EnvironmentReading> {
  return request<EnvironmentReading>('/environment/check', { method: 'POST', timeoutMs: RUN_TIMEOUT_MS })
}

/** Trace summaries posted by `agent_tracing.py`, newest first. */
export function fetchTraces(): Promise<{ traces: TraceSummary[] }> {
  return request<{ traces: TraceSummary[] }>('/agent/traces')
}

/**
 * One trace with its whole span tree, but without the payloads.
 *
 * The bodies are what make a trace megabytes, and polling re-reads this every
 * few seconds; the details sheet fetches the one span it is showing instead.
 */
export function fetchTrace(id: string): Promise<Trace> {
  return request<Trace>(`/agent/traces/${encodeURIComponent(id)}?payloads=false`, { timeoutMs: PAYLOAD_TIMEOUT_MS })
}

/** One span, with its payloads. Loaded when a span is opened. */
export function fetchSpan(traceId: string, spanId: string): Promise<Span> {
  return request<Span>(
    `/agent/traces/${encodeURIComponent(traceId)}/spans/${encodeURIComponent(spanId)}`,
    { timeoutMs: PAYLOAD_TIMEOUT_MS },
  )
}

export function clearTraces(): Promise<{ cleared: boolean, journalRemoved: string[] }> {
  return request<{ cleared: boolean, journalRemoved: string[] }>('/agent/traces', { method: 'DELETE' })
}

/**
 * The documented way to start the bridge inside the devcontainer.
 *
 * The bridge is the better source — it composes the command from its own
 * interpreter and location, so it cannot drift. But it is also the thing that
 * is down whenever this command is actually needed, hence a default. Override
 * it with `VITE_BRIDGE_COMMAND` if the setup differs.
 */
const FALLBACK_BRIDGE_COMMAND = import.meta.env.VITE_BRIDGE_COMMAND
  ?? 'cd /workspaces/VulnHunter && /home/vscode/.venv/bin/python web/server/main.py'

/** The command to start a bridge, self-reported when one is reachable. */
export async function bridgeStartCommand(): Promise<string> {
  try {
    return (await request<BridgeInfo>('/bridge/info')).command
  }
  catch {
    return FALLBACK_BRIDGE_COMMAND
  }
}

/** Requests cancellation of a bridge-owned Agent run. */
export function stopAgentTrace(id: string): Promise<{ stopRequested: boolean }> {
  return request<{ stopRequested: boolean }>(`/agent/traces/${encodeURIComponent(id)}/stop`, { method: 'POST' })
}

/** Reads the active model settings without ever returning the API key. */
export function fetchModelConfiguration(): Promise<ModelConfiguration> {
  return request<ModelConfiguration>('/model/config')
}

/** Persists the active model settings for new audit and evaluation tasks. */
export function saveModelConfiguration(payload: SaveModelConfiguration): Promise<ModelConfiguration> {
  return request<ModelConfiguration>('/model/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

/** Reads the active limit shared by audit and evaluation workers. */
export function fetchConcurrencyConfiguration(): Promise<ConcurrencyConfiguration> {
  return request<ConcurrencyConfiguration>('/settings/concurrency')
}

/** Applies and persists the shared audit/evaluation worker limit. */
export function saveConcurrencyConfiguration(maxConcurrency: number): Promise<ConcurrencyConfiguration> {
  return request<ConcurrencyConfiguration>('/settings/concurrency', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ maxConcurrency }),
  })
}

/** Audit tasks, newest first. */
export function fetchAuditTasks(): Promise<{ tasks: AuditTask[] }> {
  return request<{ tasks: AuditTask[] }>('/audit/tasks')
}

/** Queues a repository for auditing at a specific commit, whole or one function. */
export function createAuditTask(payload: AuditSubmission): Promise<AuditTask> {
  return request<AuditTask>('/audit/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

/** Token totals and a bucketed series, aggregated by the bridge. */
export function fetchTokenUsage(interval?: string): Promise<TokenUsage> {
  const query = interval ? `?interval=${encodeURIComponent(interval)}` : ''
  return request<TokenUsage>(`/agent/usage${query}`)
}

/* -------------------------------------------------------------------------- */
/* Benchmark evaluation                                                        */
/* -------------------------------------------------------------------------- */

function postJson<T>(path: string, payload: unknown, timeoutMs = PROBE_TIMEOUT_MS): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    timeoutMs,
  })
}

/** The benchmark datasets this bridge can evaluate. */
export function fetchEvalDatasets(): Promise<{ datasets: EvalDatasetDescriptor[] }> {
  return request<{ datasets: EvalDatasetDescriptor[] }>('/eval/datasets')
}

/**
 * The pairs in a dataset, filtered by the bridge.
 *
 * Projects and CWEs repeat the parameter rather than joining on a comma: a
 * project name is arbitrary text, and a name containing a comma would otherwise
 * split into two filters.
 */
export function fetchEvalDatasetItems(datasetId: string, filters: EvalFilters = {}): Promise<EvalDatasetItems> {
  const query = new URLSearchParams()
  for (const project of filters.projects ?? []) {
    if (project)
      query.append('project', project)
  }
  for (const cwe of filters.cweIds ?? []) {
    if (cwe)
      query.append('cwe', cwe)
  }
  if (filters.search?.trim())
    query.set('search', filters.search.trim())

  const suffix = query.size ? `?${query}` : ''
  return request<EvalDatasetItems>(`/eval/datasets/${encodeURIComponent(datasetId)}/items${suffix}`)
}

/** Resolves a scope without starting anything. Same code path as creating a run. */
export function previewEvalScope(datasetId: string, scope: EvalScope): Promise<EvalScopeSummary> {
  return postJson<EvalScopeSummary>('/eval/scope', { datasetId, scope })
}

/** Queues a run and returns it; nothing is cloned until a worker picks it up. */
export function createEvalRun(datasetId: string, scope: EvalScope): Promise<EvalRun> {
  return postJson<EvalRun>('/eval/runs', { datasetId, scope })
}

/** Every run, newest first, with its progress and metrics. */
export function fetchEvalRuns(): Promise<{ runs: EvalRun[] }> {
  return request<{ runs: EvalRun[] }>('/eval/runs')
}

/** One run with all its samples. Polled while the detail sheet is open. */
export function fetchEvalRun(runId: string): Promise<EvalRunDetail> {
  return request<EvalRunDetail>(`/eval/runs/${encodeURIComponent(runId)}`)
}

export function cancelEvalRun(runId: string): Promise<{ cancelled: number, run: EvalRun }> {
  return postJson<{ cancelled: number, run: EvalRun }>(`/eval/runs/${encodeURIComponent(runId)}/cancel`, {})
}

export function pauseEvalRun(runId: string): Promise<{ run: EvalRun }> {
  return postJson<{ run: EvalRun }>(`/eval/runs/${encodeURIComponent(runId)}/pause`, {})
}

export function resumeEvalRun(runId: string): Promise<{ queued: number, run: EvalRun }> {
  return postJson<{ queued: number, run: EvalRun }>(`/eval/runs/${encodeURIComponent(runId)}/resume`, {}, 30_000)
}

export function retryEvalRun(runId: string, cancelledOnly = false): Promise<{ retried: number, run: EvalRun }> {
  // Re-journaling many samples can exceed the short bridge probe timeout.
  const action = cancelledOnly ? 'retry-cancelled' : 'retry'
  return postJson<{ retried: number, run: EvalRun }>(`/eval/runs/${encodeURIComponent(runId)}/${action}`, {}, 30_000)
}

export function deleteEvalRun(runId: string): Promise<{ removed: string }> {
  return request<{ removed: string }>(`/eval/runs/${encodeURIComponent(runId)}`, { method: 'DELETE' })
}
