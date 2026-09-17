import { computed, ref } from 'vue'
import { toast } from 'vue-sonner'
import { BridgeError, fetchSnapshot, runChecks } from '@/lib/api'
import type { CheckResult, EnvironmentSnapshot } from '@/lib/types'

/**
 * Nothing here is invented. Every value the UI renders came from the bridge; if
 * the bridge cannot be reached the snapshot is empty and says so, rather than
 * falling back to sample data that would be mistaken for a real reading.
 */
const EMPTY: EnvironmentSnapshot = { checks: [], lastRun: null, source: 'unavailable' }

const snapshot = ref<EnvironmentSnapshot>(EMPTY)
const loading = ref(true)
const running = ref(false)

/** Placeholder states for the cards while a run is in flight. */
function pendingChecks(): CheckResult[] {
  return snapshot.value.checks.map(check => ({
    ...check,
    state: running.value ? 'running' : 'idle',
    latencyMs: null,
    message: null,
  }))
}

export function useEnvironment() {
  const checks = computed<CheckResult[]>(() =>
    running.value ? pendingChecks() : snapshot.value.checks,
  )

  /**
   * The reading itself, which is what the stats card summarizes. There is only
   * ever one — the one on screen — and it keeps the numbers already measured
   * while a run is in flight, so re-running does not blank the page out for the
   * length of the run.
   */
  const reading = computed<CheckResult[]>(() => snapshot.value.checks)

  const lastRun = computed(() => snapshot.value.lastRun)
  const source = computed<EnvironmentSnapshot['source']>(() => snapshot.value.source)

  async function load() {
    loading.value = true
    try {
      snapshot.value = { ...(await fetchSnapshot()), source: 'live' }
    }
    catch {
      snapshot.value = EMPTY
    }
    finally {
      loading.value = false
    }
  }

  async function run() {
    if (running.value)
      return

    running.value = true

    try {
      const next = await runChecks()
      snapshot.value = { ...next, source: 'live' }

      const failures = next.checks.filter(check => check.state === 'fail').length
      toast.success('环境检测完成', {
        description: failures === 0
          ? `全部 ${next.checks.length} 项检测通过。`
          : `${failures} 项检测未通过，见下方详情。`,
      })
    }
    catch (error) {
      // No fallback data: report the failure and leave the last real reading up.
      const reason = error instanceof BridgeError
        ? error.message
        : '无法连接桥接服务，请确认它正在运行。'
      toast.error('检测未能执行', { description: reason })
    }
    finally {
      running.value = false
    }
  }

  return {
    loading,
    running,
    checks,
    reading,
    lastRun,
    source,
    load,
    run,
  }
}
