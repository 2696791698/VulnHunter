import type { Trace, TraceSummary } from './traces'
import type { AuditTask, BridgeInfo, EnvironmentReading, TokenUsage } from './types'

/**
 * Base URL of the optional Python bridge in `server/`. It is proxied by Vite in
 * development (see `vite.config.ts`), so the default works out of the box.
 */
const API_BASE = import.meta.env.VITE_API_BASE ?? '/api'

/** The bridge may not be running — keep the probe short so the UI can say so. */
const PROBE_TIMEOUT_MS = 2500
const RUN_TIMEOUT_MS = 180_000

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

export function fetchTrace(id: string): Promise<Trace> {
  return request<Trace>(`/agent/traces/${encodeURIComponent(id)}`)
}

export function clearTraces(): Promise<{ cleared: boolean }> {
  return request<{ cleared: boolean }>('/agent/traces', { method: 'DELETE' })
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

/** Audit tasks, newest first. */
export function fetchAuditTasks(): Promise<{ tasks: AuditTask[] }> {
  return request<{ tasks: AuditTask[] }>('/audit/tasks')
}

/** Queues a repository for auditing at a specific commit. */
export function createAuditTask(payload: { url: string, commit: string }): Promise<AuditTask> {
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
