<script setup lang="ts">
import type { EvalRun, EvalRunStatus } from '@/lib/types'
import {
  CircleAlertIcon,
  CircleCheckIcon,
  ClockIcon,
  FlaskConicalIcon,
  LoaderIcon,
  PauseIcon,
} from '@lucide/vue'
import { ref } from 'vue'
import EvalRunSheet from '@/components/dashboard/EvalRunSheet.vue'
import EvalScopePicker from '@/components/dashboard/EvalScopePicker.vue'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Item, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import { useEvaluation } from '@/composables/useEvaluation'
import {
  EVAL_RUN_STATUS_LABELS,
  NO_DATA,
  elapsedLabel,
  formatMetric,
  formatRelative,
} from '@/lib/format'

const { runs, runsLoading, reachable } = useEvaluation()

const openRunId = ref<string | null>(null)

const TONE: Record<EvalRunStatus, string> = {
  queued: 'text-muted-foreground',
  running: 'text-muted-foreground animate-spin',
  paused: 'text-status-warning',
  done: 'text-status-good',
  interrupted: 'text-status-warning',
}

const STATUS_ICON: Record<EvalRunStatus, typeof ClockIcon> = {
  queued: ClockIcon,
  running: LoaderIcon,
  paused: PauseIcon,
  done: CircleCheckIcon,
  interrupted: CircleAlertIcon,
}

/** How much of a run is behind us, as a percentage for the progress bar. */
function percent(run: EvalRun): number {
  if (run.progress.total === 0)
    return 0
  return Math.round((run.progress.finished / run.progress.total) * 100)
}

/**
 * What the sample in flight is doing, which the bare finished/total cannot say:
 * a run sitting at 0/200 is either cloning or not started.
 */
const ACTIVE_LABELS = {
  cloning: '拉取中',
  running: '测评中',
} as const

function activity(run: EvalRun): string | null {
  const parts: string[] = []
  if (run.progress.cloning)
    parts.push(`${ACTIVE_LABELS.cloning} ${run.progress.cloning}`)
  if (run.progress.running)
    parts.push(`${ACTIVE_LABELS.running} ${run.progress.running}`)
  if (run.progress.queued)
    parts.push(`${run.status === 'paused' ? '待继续' : '排队'} ${run.progress.queued}`)
  return parts.length ? parts.join(' · ') : null
}

/**
 * The samples the metrics do not cover, spelled out. Without this a run that
 * lost half its samples to a broken clone looks identical to one that ran
 * everything and did badly.
 */
function coverageNote(run: EvalRun): string | null {
  const { unparsed, failed, cancelled, pending } = run.metrics
  const parts: string[] = []
  if (unparsed)
    parts.push(`${unparsed} 个样例没有结构化判定（按未命中计）`)
  if (failed)
    parts.push(`${failed} 个样例失败`)
  if (cancelled)
    parts.push(`${cancelled} 个已取消`)
  if (pending)
    parts.push(`${pending} 个还没跑完`)
  return parts.length ? parts.join(' · ') : null
}
</script>

<template>
  <section class="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
    <div class="flex flex-col gap-1">
      <h2 class="text-lg font-semibold">
        数据集测评
      </h2>
      <p class="text-muted-foreground text-sm">
        从数据集里选一个范围，把每个样例交给 agent 做一次函数级审查，再按标注比对判定结果。
      </p>
    </div>

    <EvalScopePicker @started="runId => (openRunId = runId)" />

    <Card>
      <CardHeader>
        <CardTitle>测评进度</CardTitle>
        <CardDescription>
          {{ runs.length }} 次测评，按时间倒序。点开可暂停、继续或查看每个样例的判定。
        </CardDescription>
      </CardHeader>

      <CardContent class="p-2">
        <div v-if="runsLoading" class="flex flex-col gap-1 p-1">
          <Skeleton v-for="n in 3" :key="n" class="h-16 rounded-md" />
        </div>

        <Empty v-else-if="runs.length === 0" class="min-h-40">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <FlaskConicalIcon />
            </EmptyMedia>
            <EmptyTitle>{{ reachable ? NO_DATA : '无法连接桥接服务' }}</EmptyTitle>
            <EmptyDescription>
              {{ reachable
                ? '还没有测评记录，在上面选好范围就能开始。'
                : '测评进度来自桥接服务，请先启动它再刷新页面。' }}
            </EmptyDescription>
          </EmptyHeader>
        </Empty>

        <div v-else class="flex flex-col gap-0.5">
          <Item
            v-for="run in runs"
            :key="run.id"
            as="button"
            type="button"
            size="xs"
            class="hover:bg-muted/60 focus-visible:ring-ring/50 w-full flex-col items-start rounded-md border-0 px-3 py-2.5 text-left outline-none focus-visible:ring-3"
            @click="openRunId = run.id"
          >
            <ItemContent class="gap-2">
              <div class="flex w-full flex-wrap items-center gap-2">
                <ItemTitle class="min-w-0 flex-1 truncate">
                  {{ run.title }}
                </ItemTitle>
                <Badge variant="secondary" class="shrink-0">
                  {{ run.datasetName }}
                </Badge>
                <Badge variant="outline" class="shrink-0">
                  <component :is="STATUS_ICON[run.status]" :class="TONE[run.status]" />
                  {{ EVAL_RUN_STATUS_LABELS[run.status] }}
                </Badge>
              </div>

              <div class="flex w-full items-center gap-3">
                <Progress :model-value="percent(run)" class="max-w-96 flex-1" />
                <span class="text-muted-foreground shrink-0 font-mono text-xs tabular-nums">
                  {{ run.progress.finished }} / {{ run.progress.total }}
                </span>
              </div>

              <ItemDescription class="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs">
                <span>指标覆盖 {{ run.metrics.counted }} / {{ run.metrics.total }}</span>
                <span>召回率 {{ formatMetric(run.metrics.recall) }}</span>
                <span>误报率 {{ formatMetric(run.metrics.fpr) }}</span>
                <span>F1 {{ formatMetric(run.metrics.f1) }}</span>
                <span>Pair-Correctness {{ formatMetric(run.metrics.pairCorrectness) }}</span>
              </ItemDescription>

              <ItemDescription class="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs">
                <span>{{ formatRelative(run.createdAt) }}</span>
                <template v-if="run.startedAt">
                  <span aria-hidden="true">·</span>
                  <span>历时 {{ elapsedLabel(run.startedAt, run.endedAt) }}</span>
                </template>
                <template v-if="activity(run)">
                  <span aria-hidden="true">·</span>
                  <span>{{ activity(run) }}</span>
                </template>
              </ItemDescription>

              <!-- What did not produce a measurement, so the coverage line above
                   can be read against it. -->
              <ItemDescription
                v-if="coverageNote(run)"
                class="text-xs"
                :class="run.metrics.unparsed ? 'text-status-warning' : 'text-muted-foreground'"
              >
                {{ coverageNote(run) }}
              </ItemDescription>

              <ItemDescription v-if="run.error" class="text-status-critical line-clamp-1 text-xs">
                {{ run.error }}
              </ItemDescription>
            </ItemContent>
          </Item>
        </div>
      </CardContent>
    </Card>

    <EvalRunSheet v-model:run-id="openRunId" />
  </section>
</template>
