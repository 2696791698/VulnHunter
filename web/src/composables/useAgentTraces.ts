import { computed, onMounted, onUnmounted, ref } from 'vue'
import { clearTraces as clearRemoteTraces, fetchSpan, fetchTrace, fetchTraces } from '@/lib/api'
import type { Span, Trace, TraceSummary } from '@/lib/traces'

const POLL_INTERVAL_MS = 4000

/** `unavailable` means the bridge could not be reached at all. */
export type TraceSource = 'live' | 'unavailable'

const traces = ref<TraceSummary[]>([])
const detail = ref<Trace | null>(null)
const selectedId = ref<string | null>(null)
const selectedSpan = ref<Span | null>(null)
const spanLoading = ref(false)
const source = ref<TraceSource>('unavailable')
const loading = ref(true)
const autoRefresh = ref(true)

let timer: ReturnType<typeof setInterval> | null = null
/** The revision of the trace currently in `detail`, so the poll can skip a
 * trace that has not changed instead of re-downloading it every few seconds. */
let detailRevision = -1

/**
 * Everything shown comes from the bridge's in-memory trace store. There is no
 * sample data: with no bridge, or with no agent runs, the page says so.
 *
 * Payloads are kept whole by the bridge, so the page never downloads them in
 * bulk: the tree is refreshed without them and a span is fetched individually
 * when it is opened.
 */
export function useAgentTraces() {
  const hasTraces = computed(() => traces.value.length > 0)

  function revisionOf(id: string): number {
    return traces.value.find(trace => trace.id === id)?.revision ?? -1
  }

  async function loadDetail(id: string) {
    try {
      detail.value = await fetchTrace(id)
      detailRevision = revisionOf(id)
      rebindSelected()
    }
    catch {
      detail.value = null
      detailRevision = -1
    }
  }

  /** Re-points the open span at the fresh copy, keeping the payloads it has.
   *
   * `detail` is replaced on every refresh, so the sheet would otherwise be
   * holding a stale object — and re-fetching the payloads to fix that is
   * exactly what this is avoiding. */
  function rebindSelected() {
    const current = selectedSpan.value
    if (!current || !detail.value)
      return

    const fresh = detail.value.spans.find(span => span.id === current.id)
    if (!fresh) {
      selectedSpan.value = null
      return
    }
    selectedSpan.value = { ...fresh, inputs: current.inputs, outputs: current.outputs }
  }

  /** Opens a span: its metadata immediately, its payloads a moment later. */
  async function openSpan(span: Span) {
    selectedSpan.value = span
    spanLoading.value = true
    try {
      const full = await fetchSpan(span.traceId, span.id)
      // Only if the user has not moved on to another span meanwhile.
      if (selectedSpan.value?.id === span.id)
        selectedSpan.value = full
    }
    catch {
      // Keep the metadata; the sheet renders an empty payload as "no data".
    }
    finally {
      spanLoading.value = false
    }
  }

  async function select(id: string) {
    if (id !== selectedId.value)
      selectedSpan.value = null
    selectedId.value = id
    await loadDetail(id)
  }

  async function refresh() {
    try {
      const { traces: list } = await fetchTraces()
      traces.value = list
      source.value = 'live'

      if (list.length === 0) {
        selectedId.value = null
        detail.value = null
        selectedSpan.value = null
        detailRevision = -1
        return
      }

      const stillThere = list.some(trace => trace.id === selectedId.value)
      const next = stillThere ? selectedId.value! : list[0].id
      selectedId.value = next

      // Skip the tree entirely when nothing was appended to it.
      if (revisionOf(next) !== detailRevision)
        await loadDetail(next)

      // A span that is still running has not sent its outputs yet, so it is the
      // one case where the payloads are worth re-reading.
      if (selectedSpan.value?.status === 'running')
        await openSpan(selectedSpan.value)
    }
    catch {
      // Unreachable bridge: keep no stale rows on screen.
      traces.value = []
      detail.value = null
      selectedId.value = null
      selectedSpan.value = null
      detailRevision = -1
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
    detailRevision = -1
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
    spanLoading,
    source,
    loading,
    autoRefresh,
    hasTraces,
    select,
    openSpan,
    refresh,
    clear,
    toggleAutoRefresh,
  }
}
