import { computed, onMounted, onUnmounted, ref } from 'vue'
import { clearTraces as clearRemoteTraces, fetchTrace, fetchTraces } from '@/lib/api'
import type { Span, Trace, TraceSummary } from '@/lib/traces'

const POLL_INTERVAL_MS = 4000

/** `unavailable` means the bridge could not be reached at all. */
export type TraceSource = 'live' | 'unavailable'

const traces = ref<TraceSummary[]>([])
const detail = ref<Trace | null>(null)
const selectedId = ref<string | null>(null)
const selectedSpan = ref<Span | null>(null)
const source = ref<TraceSource>('unavailable')
const loading = ref(true)
const autoRefresh = ref(true)

let timer: ReturnType<typeof setInterval> | null = null

/**
 * Everything shown comes from the bridge's in-memory trace store. There is no
 * sample data: with no bridge, or with no agent runs, the page says so.
 */
export function useAgentTraces() {
  const hasTraces = computed(() => traces.value.length > 0)

  async function select(id: string) {
    selectedId.value = id
    selectedSpan.value = null

    try {
      detail.value = await fetchTrace(id)
    }
    catch {
      detail.value = null
    }
  }

  async function refresh() {
    try {
      const { traces: list } = await fetchTraces()
      traces.value = list
      source.value = 'live'

      if (list.length === 0) {
        selectedId.value = null
        detail.value = null
        return
      }

      const stillThere = list.some(trace => trace.id === selectedId.value)
      const next = stillThere ? selectedId.value! : list[0].id
      await select(next)
    }
    catch {
      // Unreachable bridge: keep no stale rows on screen.
      traces.value = []
      detail.value = null
      selectedId.value = null
      selectedSpan.value = null
      source.value = 'unavailable'
    }
    finally {
      loading.value = false
    }
  }

  async function clear() {
    try {
      await clearRemoteTraces()
    }
    catch {
      // Clearing a bridge that is not running is a no-op.
    }

    traces.value = []
    detail.value = null
    selectedId.value = null
    selectedSpan.value = null
    source.value = 'live'
  }

  function toggleAutoRefresh() {
    autoRefresh.value = !autoRefresh.value
  }

  onMounted(async () => {
    await refresh()

    timer = setInterval(() => {
      if (autoRefresh.value && source.value === 'live' && document.visibilityState === 'visible')
        void refresh()
    }, POLL_INTERVAL_MS)
  })

  onUnmounted(() => {
    if (timer)
      clearInterval(timer)
  })

  return {
    traces,
    detail,
    selectedId,
    selectedSpan,
    source,
    loading,
    autoRefresh,
    hasTraces,
    select,
    refresh,
    clear,
    toggleAutoRefresh,
  }
}
