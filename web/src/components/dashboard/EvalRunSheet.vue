<script setup lang="ts">
import type { EvalMetricKey, EvalRunDetail, EvalSample, EvalSampleStatus } from '@/lib/types'
import {
  CircleAlertIcon,
  CircleCheckIcon,
  CircleMinusIcon,
  ClockIcon,
  GitBranchIcon,
  LoaderIcon,
  PauseIcon,
  PlayIcon,
  RotateCcwIcon,
  SquareIcon,
  Trash2Icon,
  XCircleIcon,
} from '@lucide/vue'
import { computed, ref, watch } from 'vue'
import { toast } from 'vue-sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { useEvaluation } from '@/composables/useEvaluation'
import {
  EVAL_LABEL_TEXT,
  EVAL_METRIC_LABELS,
  EVAL_RUN_STATUS_LABELS,
  EVAL_SAMPLE_STATUS_LABELS,
  EVAL_SAMPLE_TYPE_LABELS,
  NO_DATA,
  elapsedLabel,
  formatReproductionReport,
  formatMetric,
  formatRelative,
  orNoData,
} from '@/lib/format'

const props = defineProps<{ runId: string | null }>()
const emit = defineEmits<{ 'update:runId': [value: string | null] }>()

const { detail, openRun, closeRun, cancelRun, pauseRun, resumeRun, retryRun, removeRun } = useEvaluation()

const open = computed({
  // The sheet is open exactly when there is a run to show, so closing it (the
  // X, Esc, or a click outside) has to clear the selection in the page too —
  // otherwise reopening would show a stale run.
  get: () => props.runId !== null,
  set: (value: boolean) => {
    if (!value)
      onClose()
  },
})

const run = computed<EvalRunDetail | null>(() => detail.value)
const retrying = ref<'unresolved' | 'cancelled' | null>(null)
const changingPause = ref(false)
const retryable = computed(() => (run.value?.metrics.failed ?? 0) + (run.value?.metrics.unparsed ?? 0))

const TONE: Record<EvalSampleStatus, string> = {
  queued: 'text-muted-foreground',
  cloning: 'text-muted-foreground animate-pulse',
  running: 'text-muted-foreground animate-spin',
  done: 'text-status-good',
  failed: 'text-status-critical',
  cancelled: 'text-muted-foreground',
}

const STATUS_ICON: Record<EvalSampleStatus, typeof ClockIcon> = {
  queued: ClockIcon,
  cloning: GitBranchIcon,
  running: LoaderIcon,
  done: CircleCheckIcon,
  failed: CircleAlertIcon,
  cancelled: XCircleIcon,
}

/** Which rows the result table shows. */
const filter = ref<'all' | 'wrong' | 'unresolved' | 'cancelled'>('all')

const rows = computed(() => {
  const samples = run.value?.samples ?? []
  if (filter.value === 'wrong')
    return samples.filter(sample => sample.correct === false)
  if (filter.value === 'cancelled')
    return samples.filter(sample => sample.status === 'cancelled')
  if (filter.value === 'unresolved')
    return samples.filter(sample => outcome(sample) === 'unresolved')
  return samples
})

/**
 * The metric cards, in the order the label table lists them. Taking the order
 * from the same object that holds the wording means the two cannot drift apart
 * — adding a metric is one entry in one place.
 */
const METRIC_ORDER = Object.keys(EVAL_METRIC_LABELS) as EvalMetricKey[]

/**
 * What became of a sample. A verdict is only meaningful once a sample produced
 * one: one that never ran, or has not finished, is neither a hit nor a miss —
 * it is left out of the metrics, so it reads as its own thing here too. Which
 * of those it is, the 状态 column next door says.
 */
function outcome(sample: EvalSample): 'hit' | 'miss' | 'unresolved' | 'cancelled' | 'pending' {
  if (sample.status === 'cancelled')
    return 'cancelled'
  if (sample.status === 'failed')
    return 'unresolved'
  if (sample.status !== 'done')
    return 'pending'
  if (sample.prediction === null)
    return 'unresolved'
  return sample.correct ? 'hit' : 'miss'
}

const OUTCOME_LABELS = {
  hit: '命中',
  miss: '误判',
  unresolved: '无结论',
  cancelled: '已取消',
  pending: '还没跑完',
} as const

const OUTCOME_TONE = {
  hit: 'text-status-good',
  miss: 'text-status-critical',
  unresolved: 'text-status-warning',
  cancelled: 'text-muted-foreground',
  pending: 'text-muted-foreground',
} as const

const OUTCOME_ICON = {
  hit: CircleCheckIcon,
  miss: CircleAlertIcon,
  unresolved: CircleMinusIcon,
  cancelled: XCircleIcon,
  pending: ClockIcon,
} as const

// Opening the sheet fetches the detail; the poll in the composable keeps it
// current while it stays open.
watch(
  () => props.runId,
  (id) => {
    filter.value = 'all'
    if (id)
      void openRun(id)
  },
  { immediate: true },
)

function onClose() {
  closeRun()
  emit('update:runId', null)
}

async function onRemove() {
  const id = run.value?.id
  if (!id)
    return
  await removeRun(id)
  onClose()
}

async function onRetry(cancelledOnly = false) {
  const id = run.value?.id
  if (!id || retrying.value)
    return
  retrying.value = cancelledOnly ? 'cancelled' : 'unresolved'
  try {
    const { retried, error } = await retryRun(id, cancelledOnly)
    if (error)
      toast.error(cancelledOnly ? '重跑失败' : '重试失败', { description: error })
    else
      toast.success(cancelledOnly
        ? `已将 ${retried} 个已取消样例加入队列，结果计入本次测评`
        : `已将 ${retried} 个无结论样例加入队列`)
  }
  finally {
    retrying.value = null
  }
}

async function onPause() {
  const id = run.value?.id
  if (!id || changingPause.value)
    return
  changingPause.value = true
  try {
    const error = await pauseRun(id)
    if (error)
      toast.error('暂停失败', { description: error })
    else
      toast.success('测评已暂停', { description: '正在执行的样例会完成，其余样例等待手动继续。' })
  }
  finally {
    changingPause.value = false
  }
}

async function onResume() {
  const id = run.value?.id
  if (!id || changingPause.value)
    return
  changingPause.value = true
  try {
    const { queued, error } = await resumeRun(id)
    if (error)
      toast.error('继续测评失败', { description: error })
    else
      toast.success(`已继续测评，${queued} 个样例等待执行`)
  }
  finally {
    changingPause.value = false
  }
}
</script>

<template>
  <Sheet v-model:open="open">
    <!--
      Both the width and the cap have to be set on the same variant the component
      uses for its own defaults (`data-[side=right]:w-3/4` and
      `data-[side=right]:sm:max-w-sm`). A plain `w-full sm:max-w-3xl` is a
      different variant to tailwind-merge, so both survive the class merge and
      the more specific defaults win — the sheet then renders 384px wide with a
      six-column table inside it.
    -->
    <SheetContent class="gap-0 data-[side=right]:w-full data-[side=right]:sm:max-w-3xl">
      <template v-if="run">
        <SheetHeader>
          <SheetTitle class="truncate">
            {{ run.title }}
          </SheetTitle>
          <SheetDescription>
            {{ run.datasetName }} · {{ run.id }} · {{ formatRelative(run.createdAt) }}
          </SheetDescription>
        </SheetHeader>

        <Separator />

        <ScrollArea class="min-h-0 flex-1">
          <div class="flex flex-col gap-4 p-4">
            <div class="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div
                v-for="key in METRIC_ORDER"
                :key="key"
                class="rounded-lg border p-3"
              >
                <div class="text-muted-foreground text-xs">
                  {{ EVAL_METRIC_LABELS[key] }}
                </div>
                <div class="mt-1 font-mono text-sm font-medium">
                  {{ formatMetric(run.metrics[key]) }}
                </div>
              </div>
            </div>

            <div class="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs">
              <span>指标覆盖 {{ run.metrics.counted }} / {{ run.metrics.total }} 个样例</span>
              <span>TP {{ run.metrics.confusion.tp }}</span>
              <span>FP {{ run.metrics.confusion.fp }}</span>
              <span>TN {{ run.metrics.confusion.tn }}</span>
              <span>FN {{ run.metrics.confusion.fn }}</span>
              <span>配对 {{ run.metrics.pairs.correct }} / {{ run.metrics.pairs.total }} 全对</span>
              <span>配对双判有漏洞 {{ run.metrics.pairs.vulnerable }}</span>
              <span>配对双判无漏洞 {{ run.metrics.pairs.nonVulnerable }}</span>
              <span>配对判反 {{ run.metrics.pairs.reversed }}</span>
            </div>

            <Alert v-if="run.status === 'paused'">
              <PauseIcon />
              <AlertTitle>{{ run.pausedReason === 'restart' ? '服务重启后已暂停' : '测评已暂停' }}</AlertTitle>
              <AlertDescription>
                不会启动新的样例。点击下方“继续测评”后，待运行的样例才会入队；已完成的判定会保留。
                <template v-if="run.progress.cloning || run.progress.running">
                  当前已开始的样例会继续完成。
                </template>
              </AlertDescription>
            </Alert>

            <p v-if="run.resumedAt" class="text-muted-foreground text-xs">
              上次续测将 {{ run.resumedSamples }} 个待运行样例加入队列（{{ formatRelative(run.resumedAt) }}）。
            </p>

            <Alert v-if="run.metrics.unparsed">
              <CircleMinusIcon />
              <AlertTitle>{{ run.metrics.unparsed }} 个样例没有结构化判定</AlertTitle>
              <AlertDescription>
                这些样例跑了，但模型没有返回符合 schema 的 0/1 判定和对应报告。
                它们在指标里按<strong>未命中</strong>计。
              </AlertDescription>
            </Alert>

            <Alert v-if="run.metrics.excluded">
              <XCircleIcon />
              <AlertTitle>{{ run.metrics.excluded }} 个样例没有跑</AlertTitle>
              <AlertDescription>
                失败 {{ run.metrics.failed }} 个、已取消 {{ run.metrics.cancelled }} 个，
                这些<strong>不计入</strong>上面的指标 —— 它们没有测到模型，当成误判会把一个
                没跑完的测评说成模型全错。
                <!--
                  The samples still in flight are a gap in the coverage too, but
                  not the same one: they are being measured right now, so they
                  are named separately rather than folded into "did not run".
                -->
                <template v-if="run.metrics.pending">
                  另有 {{ run.metrics.pending }} 个还没跑完，结论出来之前同样不进去。
                </template>
                指标覆盖的就是上面那 {{ run.metrics.counted }} 个样例。
              </AlertDescription>
            </Alert>

            <Alert v-if="run.error" variant="destructive">
              <CircleAlertIcon />
              <AlertTitle>测评出错</AlertTitle>
              <AlertDescription>{{ run.error }}</AlertDescription>
            </Alert>

            <div class="flex flex-wrap items-center gap-2">
              <ToggleGroup v-model="filter" type="single" variant="outline" size="sm">
                <ToggleGroupItem value="all">
                  全部 {{ run.samples.length }}
                </ToggleGroupItem>
                <ToggleGroupItem value="wrong">
                  只看误判
                </ToggleGroupItem>
                <ToggleGroupItem value="unresolved">
                  只看无结论
                </ToggleGroupItem>
                <ToggleGroupItem v-if="run.metrics.cancelled" value="cancelled">
                  已取消 {{ run.metrics.cancelled }}
                </ToggleGroupItem>
              </ToggleGroup>
            </div>

            <div class="rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>样例</TableHead>
                    <TableHead>版本</TableHead>
                    <TableHead>标注</TableHead>
                    <TableHead>判定</TableHead>
                    <TableHead>结果</TableHead>
                    <TableHead>状态</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow v-for="sample in rows" :key="sample.id">
                    <TableCell class="max-w-44">
                      <div class="truncate font-mono text-xs">{{ sample.itemId }}</div>
                      <div class="text-muted-foreground truncate text-xs">
                        {{ orNoData(sample.projectName) }}
                      </div>
                      <div class="text-muted-foreground truncate font-mono text-xs">
                        {{ orNoData(sample.filePath) }}
                      </div>
                    </TableCell>
                    <TableCell class="text-xs">
                      {{ EVAL_SAMPLE_TYPE_LABELS[sample.type] }}
                    </TableCell>
                    <TableCell class="text-xs">
                      {{ EVAL_LABEL_TEXT[sample.truth] }}
                    </TableCell>
                    <TableCell class="text-xs">
                      {{ sample.prediction ? EVAL_LABEL_TEXT[sample.prediction] : NO_DATA }}
                      <details v-if="formatReproductionReport(sample.verdict)" class="mt-1 max-w-72 text-muted-foreground">
                        <summary class="cursor-pointer">查看复现报告</summary>
                        <pre class="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px]">{{ formatReproductionReport(sample.verdict) }}</pre>
                      </details>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" :class="OUTCOME_TONE[outcome(sample)]">
                        <component :is="OUTCOME_ICON[outcome(sample)]" />
                        {{ OUTCOME_LABELS[outcome(sample)] }}
                      </Badge>
                    </TableCell>
                    <TableCell class="max-w-40">
                      <div class="flex items-center gap-1.5 text-xs">
                        <component
                          :is="STATUS_ICON[sample.status]"
                          class="size-3.5 shrink-0"
                          :class="TONE[sample.status]"
                        />
                        {{ EVAL_SAMPLE_STATUS_LABELS[sample.status] }}
                      </div>
                      <div v-if="sample.error" class="text-status-critical truncate text-xs">
                        {{ sample.error }}
                      </div>
                      <div v-else-if="sample.startedAt" class="text-muted-foreground text-xs">
                        用时 {{ elapsedLabel(sample.startedAt, sample.endedAt) }}
                      </div>
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </div>

            <p v-if="rows.length === 0" class="text-muted-foreground text-sm">
              这个筛选条件下没有样例。
            </p>
          </div>
        </ScrollArea>

        <Separator />

        <SheetFooter class="flex-row flex-wrap items-center gap-2">
          <Badge variant="outline">
            {{ EVAL_RUN_STATUS_LABELS[run.status] }}
          </Badge>
          <Button
            v-if="run.status === 'paused'"
            size="sm"
            :disabled="changingPause || (run.progress.queued === 0 && !run.samples.some(sample => sample.error === '服务重启，样例中断'))"
            @click="onResume"
          >
            <PlayIcon data-icon="inline-start" />
            {{ changingPause ? '正在继续…' : '继续测评' }}
          </Button>
          <Button
            v-else-if="run.status === 'queued' || run.status === 'running'"
            variant="outline"
            size="sm"
            :disabled="changingPause || run.progress.queued === 0"
            @click="onPause"
          >
            <PauseIcon data-icon="inline-start" />
            {{ changingPause ? '正在暂停…' : '暂停测评' }}
          </Button>
          <Button
            variant="outline"
            size="sm"
            :disabled="run.progress.queued === 0"
            @click="cancelRun(run.id)"
          >
            <SquareIcon data-icon="inline-start" />
            取消未开始的
          </Button>
          <Button
            variant="outline"
            size="sm"
            :disabled="run.status === 'paused' || retryable === 0 || retrying !== null"
            @click="onRetry()"
          >
            <RotateCcwIcon data-icon="inline-start" />
            {{ retrying === 'unresolved' ? '正在重试…' : `重试无结论的 (${retryable})` }}
          </Button>
          <Button
            v-if="run.metrics.cancelled > 0"
            variant="outline"
            size="sm"
            :disabled="run.status === 'paused' || retrying !== null"
            @click="onRetry(true)"
          >
            <RotateCcwIcon data-icon="inline-start" />
            {{ retrying === 'cancelled' ? '正在重跑…' : `重跑已取消 (${run.metrics.cancelled})` }}
          </Button>
          <Button variant="ghost" size="sm" class="ml-auto" @click="onRemove">
            <Trash2Icon data-icon="inline-start" />
            移除这次测评
          </Button>
        </SheetFooter>
      </template>

      <template v-else>
        <SheetHeader>
          <SheetTitle>测评详情</SheetTitle>
          <SheetDescription>正在读取…</SheetDescription>
        </SheetHeader>
      </template>
    </SheetContent>
  </Sheet>
</template>
