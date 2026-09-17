import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { fetchTokenUsage } from '@/lib/api'
import type { TokenUsage, UsageInterval, UsageTotals } from '@/lib/types'

const POLL_INTERVAL_MS = 5000

/**
 * Token consumption, as aggregated by the bridge from the model spans the
 * tracer posted. Nothing is estimated here: with no agent run there is no
 * usage to report, and the page says so.
 */
const EMPTY: TokenUsage = { totals: null, models: [], buckets: [], interval: '', intervals: [] }

const usage = ref<TokenUsage>(EMPTY)
const loading = ref(true)

/** Empty means "whatever the bridge defaults to"; the reply then fills it in. */
const interval = ref('')
const intervals = ref<UsageInterval[]>([])

let timer: ReturnType<typeof setInterval> | null = null

const TOTALS_FIELDS = [
  'requests',
  'inputTokens',
  'newInputTokens',
  'outputTokens',
  'cacheReadTokens',
  'cacheCreationTokens',
  'totalTokens',
  'cacheHitRate',
] as const

function sameTotals(a: UsageTotals | null, b: UsageTotals | null): boolean {
  if (a === b)
    return true
  if (!a || !b)
    return false
  return TOTALS_FIELDS.every(field => a[field] === b[field])
}

/**
 * Whether two polls describe the same numbers.
 *
 * Every poll answers with freshly built objects, but the tokens behind them only
 * move when the agent runs. Assigning the new object regardless would rebuild
 * every computed downstream — and Unovis clears its crosshair and tooltip the
 * moment its data identity changes, so a reader hovering the trend chart would
 * watch the readout vanish under the cursor every five seconds.
 */
function sameUsage(a: TokenUsage, b: TokenUsage): boolean {
  return a.interval === b.interval
    && a.models.length === b.models.length
    && a.models.every((model, index) => model === b.models[index])
    && a.intervals.length === b.intervals.length
    && a.intervals.every((item, index) => item.value === b.intervals[index].value && item.label === b.intervals[index].label)
    && a.buckets.length === b.buckets.length
    && a.buckets.every((bucket, index) => bucket.key === b.buckets[index].key && sameTotals(bucket, b.buckets[index]))
    && sameTotals(a.totals, b.totals)
}

export function useTokenUsage() {
  const totals = computed(() => usage.value.totals)
  const models = computed(() => usage.value.models)
  const buckets = computed(() => usage.value.buckets)
  const hasData = computed(() => usage.value.totals !== null)

  async function refresh() {
    try {
      const payload = await fetchTokenUsage(interval.value || undefined)
      if (!sameUsage(usage.value, payload))
        usage.value = payload
      if (!interval.value)
        interval.value = payload.interval
      intervals.value = payload.intervals
    }
    catch {
      usage.value = EMPTY
      intervals.value = []
    }
    finally {
      loading.value = false
    }
  }

  // Changing the bucket size is a different query, so it does not wait for the
  // next poll to show up.
  watch(interval, () => {
    if (interval.value)
      void refresh()
  })

  onMounted(() => {
    void refresh()

    timer = setInterval(() => {
      if (document.visibilityState === 'visible')
        void refresh()
    }, POLL_INTERVAL_MS)
  })

  onUnmounted(() => {
    if (timer)
      clearInterval(timer)
  })

  return { totals, models, buckets, interval, intervals, hasData, loading, refresh }
}
