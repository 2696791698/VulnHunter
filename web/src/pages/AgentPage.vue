<script setup lang="ts">
import type { Span, SpanKind, TraceSummary } from '@/lib/traces'
import {
  BlocksIcon,
  CircleAlertIcon,
  CircleCheckIcon,
  LoaderIcon,
  RefreshCwIcon,
  SparkleIcon,
  Trash2Icon,
  WaypointsIcon,
  WrenchIcon,
} from '@lucide/vue'
import { computed } from 'vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import SpanDetailsSheet from '@/components/dashboard/SpanDetailsSheet.vue'
import TraceWaterfall from '@/components/dashboard/TraceWaterfall.vue'
import { useAgentTraces } from '@/composables/useAgentTraces'
import { NO_DATA, formatDuration, formatRelative, formatTokens } from '@/lib/format'
import { SPAN_KIND_LABELS, SPAN_STATUS_LABELS } from '@/lib/traces'

const {
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
} = useAgentTraces()

/* A legend is always present for the span kinds — the icons and the text labels
 * carry identity, the colours only reinforce it. */
const KINDS: { kind: SpanKind, icon: object, color: string }[] = [
  { kind: 'chain', icon: BlocksIcon, color: 'text-trace-chain' },
  { kind: 'model', icon: SparkleIcon, color: 'text-trace-model' },
  { kind: 'tool', icon: WrenchIcon, color: 'text-trace-tool' },
]

const STATUS_TONE = {
  ok: 'text-status-good',
  error: 'text-status-critical',
  running: 'text-muted-foreground animate-pulse',
} as const

const STATUS_ICON = {
  ok: CircleCheckIcon,
  error: CircleAlertIcon,
  running: LoaderIcon,
} as const

const spanSheetOpen = computed({
  get: () => selectedSpan.value !== null,
  set: (value: boolean) => {
    if (!value)
      selectedSpan.value = null
  },
})

function traceDuration(trace: TraceSummary): number {
  const from = Date.parse(trace.startedAt)
  const to = trace.endedAt ? Date.parse(trace.endedAt) : Date.now()
  return to - from
}

function openSpan(span: Span) {
  selectedSpan.value = span
}

const sourceLabel = computed(() =>
  source.value === 'live' ? `${traces.value.length} 条轨迹` : '未连接',
)
</script>

<template>
  <section class="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
    <div class="flex flex-col gap-1">
      <h2 class="text-lg font-semibold">
        Agent 监控
      </h2>
      <p class="text-muted-foreground text-sm">
        逐层展开一次 agent 运行的 span 树：模型调用、工具调用与子 agent 各自的耗时、输入输出和 token 用量。
        点任意一行查看细节。
      </p>
    </div>

    <div class="grid gap-4 xl:grid-cols-[22rem_minmax(0,1fr)]">
      <Card class="gap-0 overflow-hidden">
        <CardHeader class="border-b pb-4">
          <CardTitle>运行轨迹</CardTitle>
          <CardDescription>{{ sourceLabel }}</CardDescription>
          <CardAction>
            <div class="flex items-center gap-1">
              <Tooltip>
                <TooltipTrigger as-child>
                  <!-- The ghost variant hard-codes `hover:text-foreground`, which
                       would clobber the "on" colour the moment the pointer lands
                       on it. Restating it under `hover:` keeps the green. -->
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    :class="autoRefresh && source === 'live' && 'text-status-good hover:text-status-good'"
                    :aria-label="autoRefresh ? '关闭自动刷新' : '开启自动刷新'"
                    @click="toggleAutoRefresh"
                  >
                    <WaypointsIcon />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="top">
                  {{ autoRefresh ? '自动刷新已开启' : '自动刷新已关闭' }}
                </TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger as-child>
                  <Button variant="ghost" size="icon-sm" aria-label="立即刷新" @click="refresh">
                    <RefreshCwIcon />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="top">
                  立即刷新
                </TooltipContent>
              </Tooltip>

              <Tooltip>
                <TooltipTrigger as-child>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label="清空轨迹"
                    :disabled="!hasTraces"
                    @click="clear"
                  >
                    <Trash2Icon />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="top">
                  清空轨迹
                </TooltipContent>
              </Tooltip>
            </div>
          </CardAction>
        </CardHeader>

        <CardContent class="p-2">
          <div v-if="loading" class="flex flex-col gap-2 p-2">
            <Skeleton v-for="n in 3" :key="n" class="h-12 rounded-lg" />
          </div>

          <Empty v-else-if="!hasTraces" class="min-h-56">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <WaypointsIcon />
              </EmptyMedia>
              <EmptyTitle>{{ source === 'live' ? '还没有运行轨迹' : NO_DATA }}</EmptyTitle>
              <EmptyDescription>
                {{ source === 'live'
                  ? '桥接服务已连接，但还没有 agent 运行记录。跑一次审计后 span 会实时出现在这里。'
                  : '无法连接桥接服务，请确认它正在运行。' }}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>

          <ScrollArea v-else class="max-h-[60vh]">
            <div class="flex flex-col gap-0.5">
              <button
                v-for="trace in traces"
                :key="trace.id"
                type="button"
                class="hover:bg-muted/60 focus-visible:ring-ring/50 flex w-full flex-col gap-1 rounded-md px-3 py-2 text-left outline-none focus-visible:ring-3"
                :class="trace.id === selectedId && 'bg-muted'"
                @click="select(trace.id)"
              >
                <span class="flex items-center gap-2">
                  <component
                    :is="STATUS_ICON[trace.status]"
                    class="size-3.5 shrink-0"
                    :class="STATUS_TONE[trace.status]"
                  />
                  <span class="truncate text-sm font-medium">{{ trace.name }}</span>
                  <span class="text-muted-foreground ml-auto shrink-0 font-mono text-xs tabular-nums">
                    {{ formatDuration(traceDuration(trace)) }}
                  </span>
                </span>

                <span class="text-muted-foreground flex items-center gap-1.5 pl-5.5 text-xs">
                  <span>{{ formatRelative(trace.startedAt) }}</span>
                  <span aria-hidden="true">·</span>
                  <span>{{ trace.spanCount }} spans</span>
                  <template v-if="trace.usage?.totalTokens">
                    <span aria-hidden="true">·</span>
                    <span>{{ formatTokens(trace.usage.totalTokens) }} tok</span>
                  </template>
                  <Badge v-if="trace.errorCount" variant="destructive" class="ml-auto h-4 px-1.5 text-[10px]">
                    {{ trace.errorCount }} 错误
                  </Badge>
                </span>
              </button>
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Card class="gap-0 overflow-hidden">
        <CardHeader class="border-b pb-4">
          <CardTitle class="truncate">
            {{ detail?.name ?? '轨迹详情' }}
          </CardTitle>
          <CardDescription>
            <template v-if="detail">
              {{ formatRelative(detail.startedAt) }} · 共 {{ formatDuration(traceDuration(detail)) }} ·
              {{ detail.spanCount }} 个 span
              <template v-if="detail.usage?.totalTokens">
                · {{ formatTokens(detail.usage.totalTokens) }} tokens
              </template>
            </template>
            <template v-else>
              从左侧选一条轨迹查看 span 树
            </template>
          </CardDescription>
          <CardAction>
            <Badge v-if="detail" variant="outline">
              <component :is="STATUS_ICON[detail.status]" :class="STATUS_TONE[detail.status]" />
              {{ SPAN_STATUS_LABELS[detail.status] }}
            </Badge>
          </CardAction>
        </CardHeader>

        <CardContent class="p-3">
          <Skeleton v-if="loading" class="h-64 rounded-lg" />

          <Empty v-else-if="!detail" class="min-h-64">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <BlocksIcon />
              </EmptyMedia>
              <EmptyTitle>没有选中的轨迹</EmptyTitle>
              <EmptyDescription>选一条轨迹后，这里会显示它完整的 span 树。</EmptyDescription>
            </EmptyHeader>
          </Empty>

          <TraceWaterfall
            v-else
            :trace="detail"
            :selected-span-id="selectedSpan?.id ?? null"
            @select="openSpan"
          />

          <div v-if="detail" class="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 border-t pt-3">
            <span
              v-for="entry in KINDS"
              :key="entry.kind"
              class="text-muted-foreground flex items-center gap-1.5 text-xs"
            >
              <component :is="entry.icon" class="size-3.5" :class="entry.color" />
              {{ SPAN_KIND_LABELS[entry.kind] }}
            </span>
            <span class="text-muted-foreground ml-auto text-xs">
              点击任意一行查看输入输出
            </span>
          </div>
        </CardContent>
      </Card>
    </div>

    <SpanDetailsSheet v-model:open="spanSheetOpen" :span="selectedSpan" />
  </section>
</template>
