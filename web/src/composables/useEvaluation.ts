import type {
  EvalDatasetDescriptor,
  EvalDatasetItems,
  EvalFilters,
  EvalRun,
  EvalRunDetail,
  EvalScope,
  EvalScopeSummary,
} from '@/lib/types'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import {
  BridgeError,
  cancelEvalRun,
  createEvalRun,
  deleteEvalRun,
  fetchEvalDatasetItems,
  fetchEvalDatasets,
  fetchEvalRun,
  fetchEvalRuns,
  pauseEvalRun,
  previewEvalScope,
  resumeEvalRun,
  retryEvalRun,
} from '@/lib/api'

const POLL_INTERVAL_MS = 4000

/** Run statuses that still mean the worker has something to do. */
const ACTIVE = ['queued', 'running']

const datasets = ref<EvalDatasetDescriptor[]>([])
const datasetsLoading = ref(true)
const datasetId = ref<string | null>(null)
const items = ref<EvalDatasetItems | null>(null)
const itemsLoading = ref(false)
const preview = ref<EvalScopeSummary | null>(null)
/** True when the last preview attempt could not be answered at all. */
const previewUnavailable = ref(false)

const runs = ref<EvalRun[]>([])
const runsLoading = ref(true)
const detail = ref<EvalRunDetail | null>(null)

/**
 * Whether the bridge answered at all. It is the only source of everything on
 * this page, so when it is down the page says so rather than showing an empty
 * dataset that reads like a real one with nothing in it.
 */
const reachable = ref(true)

let timer: ReturnType<typeof setInterval> | null = null
/** Guards the preview against out-of-order answers while the scope is edited. */
let previewSequence = 0

export function useEvaluation() {
  const hasActive = computed(() => runs.value.some(run => ACTIVE.includes(run.status)))
  const dataset = computed(() => datasets.value.find(item => item.id === datasetId.value) ?? null)

  /**
   * Records whether the bridge answered, then rethrows.
   *
   * A `BridgeError` is the bridge refusing a request, so it is up and reachable;
   * anything else is a fetch that never landed. The page tells those two apart,
   * because "the dataset is empty" and "there is no bridge" look identical on
   * screen otherwise.
   */
  async function load<T>(request: Promise<T>): Promise<T> {
    try {
      const value = await request
      reachable.value = true
      return value
    }
    catch (error) {
      reachable.value = error instanceof BridgeError
      throw error
    }
  }

  /** Datasets, and the items of the first one — the page opens on something. */
  async function loadDatasets() {
    datasetsLoading.value = true
    try {
      const response = await load(fetchEvalDatasets())
      datasets.value = response.datasets
      if (!datasets.value.some(item => item.id === datasetId.value))
        datasetId.value = datasets.value[0]?.id ?? null
      if (datasetId.value)
        await selectDataset(datasetId.value)
    }
    catch {
      datasets.value = []
      items.value = null
    }
    finally {
      datasetsLoading.value = false
    }
  }

  async function selectDataset(id: string, filters: EvalFilters = {}) {
    if (datasetId.value !== id)
      preview.value = null
    datasetId.value = id
    await loadItems(filters)
  }

  /**
   * The rows the selection table shows. The bridge filters them, so a row on
   * screen is always a row a scope can select.
   */
  async function loadItems(filters: EvalFilters = {}) {
    const id = datasetId.value
    if (!id) {
      items.value = null
      return
    }

    itemsLoading.value = true
    try {
      items.value = await load(fetchEvalDatasetItems(id, filters))
    }
    catch {
      items.value = null
    }
    finally {
      itemsLoading.value = false
    }
  }

  /**
   * The bridge resolves the scope, so the count shown before submitting is the
   * count that will be created. Answers that arrive out of order are dropped:
   * only the newest request is allowed to write the preview.
   */
  async function refreshPreview(scope: EvalScope) {
    const id = datasetId.value
    if (!id) {
      preview.value = null
      return
    }

    const sequence = ++previewSequence
    try {
      const summary = await previewEvalScope(id, scope)
      if (sequence !== previewSequence)
        return
      preview.value = summary
      previewUnavailable.value = false
    }
    catch {
      if (sequence !== previewSequence)
        return
      // No summary to show, and "no summary" has to read differently from
      // "still working on it" — otherwise a down bridge looks like a slow one.
      preview.value = null
      previewUnavailable.value = true
    }
  }

  async function refreshRuns() {
    try {
      const response = await load(fetchEvalRuns())
      runs.value = response.runs
    }
    catch {
      runs.value = []
    }
    finally {
      runsLoading.value = false
    }
  }

  /** Opens the detail sheet, and keeps it current while it is open. */
  async function openRun(runId: string) {
    try {
      detail.value = await fetchEvalRun(runId)
    }
    catch {
      detail.value = null
    }
  }

  function closeRun() {
    detail.value = null
  }

  /** Returns the queued run, or the reason it could not be queued. */
  async function startRun(scope: EvalScope): Promise<{ run: EvalRun | null, error: string | null }> {
    if (!datasetId.value)
      return { run: null, error: '还没有选择数据集。' }

    try {
      const run = await createEvalRun(datasetId.value, scope)
      runs.value = [run, ...runs.value]
      return { run, error: null }
    }
    catch (error) {
      return {
        run: null,
        error: error instanceof BridgeError ? error.message : '无法连接桥接服务，请确认它正在运行。',
      }
    }
  }

  /** Returns an error message on failure, null on success. */
  async function mutate(action: () => Promise<unknown>): Promise<string | null> {
    try {
      await action()
    }
    catch (error) {
      return error instanceof BridgeError ? error.message : '无法连接桥接服务，请确认它正在运行。'
    }

    await refreshRuns()
    if (detail.value)
      await openRun(detail.value.id)
    return null
  }

  const cancelRun = (runId: string) => mutate(() => cancelEvalRun(runId))
  const pauseRun = (runId: string) => mutate(() => pauseEvalRun(runId))
  async function resumeRun(runId: string): Promise<{ queued: number, error: string | null }> {
    try {
      const { queued } = await resumeEvalRun(runId)
      await refreshRuns()
      if (detail.value?.id === runId)
        await openRun(runId)
      return { queued, error: null }
    }
    catch (error) {
      return {
        queued: 0,
        error: error instanceof BridgeError ? error.message : '无法连接桥接服务，请确认它正在运行。',
      }
    }
  }
  async function retryRun(runId: string, cancelledOnly = false): Promise<{ retried: number, error: string | null }> {
    try {
      const { retried } = await retryEvalRun(runId, cancelledOnly)
      await refreshRuns()
      if (detail.value?.id === runId)
        await openRun(runId)
      return { retried, error: null }
    }
    catch (error) {
      return {
        retried: 0,
        error: error instanceof BridgeError ? error.message : '无法连接桥接服务，请确认它正在运行。',
      }
    }
  }

  async function removeRun(runId: string) {
    const failure = await mutate(() => deleteEvalRun(runId))
    if (failure === null && detail.value?.id === runId)
      detail.value = null
    return failure
  }

  onMounted(() => {
    void loadDatasets()
    void refreshRuns()

    timer = setInterval(async () => {
      if (document.visibilityState !== 'visible')
        return
      await refreshRuns()
      // The open sheet is the thing being watched, so it is refreshed on the
      // same tick. A paused run can still have samples that were already in
      // flight when pause was pressed; keep its detail current until they end.
      const watched = runs.value.find(item => item.id === detail.value?.id)
      if (watched && (ACTIVE.includes(watched.status)
        || (watched.status === 'paused' && (watched.progress.cloning > 0 || watched.progress.running > 0))))
        await openRun(watched.id)
    }, POLL_INTERVAL_MS)
  })

  onUnmounted(() => {
    if (timer)
      clearInterval(timer)
    timer = null
  })

  return {
    datasets,
    datasetsLoading,
    datasetId,
    dataset,
    items,
    itemsLoading,
    preview,
    previewUnavailable,
    runs,
    runsLoading,
    detail,
    reachable,
    hasActive,
    loadDatasets,
    selectDataset,
    loadItems,
    refreshPreview,
    refreshRuns,
    openRun,
    closeRun,
    startRun,
    cancelRun,
    pauseRun,
    resumeRun,
    retryRun,
    removeRun,
  }
}
