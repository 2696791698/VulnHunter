<script setup lang="ts">
import type { Span, SpanKind, Trace } from '@/lib/traces'
import type { Component } from 'vue'
import { BlocksIcon, CircleAlertIcon, SparkleIcon, WrenchIcon } from '@lucide/vue'
import { computed, ref } from 'vue'
import { Badge } from '@/components/ui/badge'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { formatDuration } from '@/lib/format'
import { SPAN_KIND_LABELS } from '@/lib/traces'

const props = defineProps<{
  trace: Trace
  selectedSpanId: string | null
}>()

const emit = defineEmits<{ select: [span: Span] }>()

/* Kind is carried by both the icon shape and the colour, so the bars stay
 * readable when colour is unavailable. */
const KIND_ICON: Record<SpanKind, Component> = {
  chain: BlocksIcon,
  model: SparkleIcon,
  tool: WrenchIcon,
}

const KIND_COLOR: Record<SpanKind, string> = {
  chain: 'text-trace-chain',
  model: 'text-trace-model',
  tool: 'text-trace-tool',
}

const KIND_BAR: Record<SpanKind, string> = {
  chain: 'bg-trace-chain',
  model: 'bg-trace-model',
  tool: 'bg-trace-tool',
}

interface Row {
  span: Span
  depth: number
  offset: number
  width: number
  durationMs: number
}

const rows = computed<Row[]>(() => {
  const spans = props.trace.spans
  if (spans.length === 0)
    return []

  const children = new Map<string | null, Span[]>()
  for (const span of spans) {
    const siblings = children.get(span.parentId)
    if (siblings)
      siblings.push(span)
    else
      children.set(span.parentId, [span])
  }
  for (const siblings of children.values())
    siblings.sort((a, b) => a.startedAt.localeCompare(b.startedAt))

  const now = Date.now()
  const start = Math.min(...spans.map(span => Date.parse(span.startedAt)))
  const end = Math.max(...spans.map(span => (span.endedAt ? Date.parse(span.endedAt) : now)))
  const total = Math.max(end - start, 1)

  const out: Row[] = []

  const seen = new Set<string>()

  function walk(span: Span, depth: number) {
    if (seen.has(span.id))
      return
    seen.add(span.id)

    const from = Date.parse(span.startedAt)
    const to = span.endedAt ? Date.parse(span.endedAt) : now
    out.push({
      span,
      depth,
      offset: ((from - start) / total) * 100,
      // A floor so a very short span is still a visible mark.
      width: Math.max(((to - from) / total) * 100, 0.6),
      durationMs: to - from,
    })
    for (const child of children.get(span.id) ?? [])
      walk(child, depth + 1)
  }

  // A root is a span with no parent, or one whose parent is not in the trace.
  // Data written before the tree was repaired has spans that never attached to
  // a root at all, and walking only the parentless ones would render nothing.
  const ids = new Set(spans.map(span => span.id))
  for (const span of spans) {
    if (span.parentId === null || !ids.has(span.parentId))
      walk(span, 0)
  }

  return out
})

const list = ref<HTMLElement | null>(null)

/** A span the exception was raised in, as opposed to one it merely crossed. */
function isFailure(span: Span): boolean {
  return span.status === 'error' && !span.propagated
}

/** The failing rows, in the order the tree draws them. */
const failureIds = computed(() =>
  rows.value.filter(row => isFailure(row.span)).map(row => row.span.id),
)

/** Which failure the header's "上一处 / 下一处" buttons are on.
 *
 * The span id, not a position, because the trace object is replaced on every
 * poll and an index would silently reset under whoever is stepping through. */
const currentFailureId = ref<string | null>(null)

/** Published for the header, which is where those buttons live. */
const failureNav = computed(() => {
  const ids = failureIds.value
  const at = currentFailureId.value === null ? -1 : ids.indexOf(currentFailureId.value)
  return { count: ids.length, position: at < 0 ? 1 : at + 1 }
})

/** The first line of an error is where the cause is stated; the rest is stack. */
function errorLine(error: string | null): string {
  const line = (error ?? '').split('\n', 1)[0]?.trim() ?? ''
  return line.length > 160 ? `${line.slice(0, 160)}…` : line
}

function scrollToSpan(spanId: string) {
  list.value
    ?.querySelector(`[data-span-failure="${CSS.escape(spanId)}"]`)
    ?.scrollIntoView({ block: 'center', behavior: 'smooth' })
}

/** Steps to the next (or previous) failure and wraps at both ends.
 *
 * A trace can fail in more than one place, and a tree of hundreds of rows hides
 * all of them, so this walks the list instead of always landing on the first.
 * Before one has been located, either button goes to the first failure. */
function stepFailure(delta: number) {
  const ids = failureIds.value
  if (ids.length === 0)
    return

  const at = currentFailureId.value === null ? -1 : ids.indexOf(currentFailureId.value)
  const next = at < 0 ? 0 : (at + delta + ids.length) % ids.length
  const target = ids[next]
  if (target === undefined)
    return

  currentFailureId.value = target
  scrollToSpan(target)
}

defineExpose({
  failureNav,
  previousFailure: () => stepFailure(-1),
  nextFailure: () => stepFailure(1),
})
</script>

<template>
  <Empty v-if="rows.length === 0" class="min-h-64">
    <EmptyHeader>
      <EmptyMedia variant="icon">
        <BlocksIcon />
      </EmptyMedia>
      <EmptyTitle>这条轨迹还没有 span</EmptyTitle>
      <EmptyDescription>轨迹刚建立时可能只有根节点，稍等片刻。</EmptyDescription>
    </EmptyHeader>
  </Empty>

  <div v-else ref="list" class="flex flex-col">
    <Tooltip v-for="row in rows" :key="row.span.id">
      <TooltipTrigger as-child>
        <button
          type="button"
          class="hover:bg-muted/60 focus-visible:ring-ring/50 grid w-full grid-cols-[minmax(8rem,14rem)_1fr_5rem] items-center gap-3 rounded-md px-2 py-1 text-left outline-none focus-visible:ring-3"
          :class="row.span.id === selectedSpanId && 'bg-muted'"
          :data-span-failure="isFailure(row.span) ? row.span.id : undefined"
          @click="emit('select', row.span)"
        >
          <span
            class="flex min-w-0 items-center gap-1.5"
            :style="{ paddingLeft: `${row.depth * 12}px` }"
          >
            <component :is="KIND_ICON[row.span.kind]" class="size-3.5 shrink-0" :class="KIND_COLOR[row.span.kind]" />
            <span
              class="truncate text-xs"
              :class="isFailure(row.span) && 'text-status-critical font-medium'"
            >{{ row.span.name }}</span>
            <template v-if="isFailure(row.span)">
              <!-- Only the span the exception was raised in is marked. The spans
                   it passed through on the way out reported the error too, but
                   flagging them as well buries the one row worth looking at. -->
              <CircleAlertIcon class="text-status-critical size-3 shrink-0" />
              <Badge variant="destructive" class="h-4 shrink-0 px-1.5 text-[10px]">
                失败
              </Badge>
            </template>
            <Badge v-else-if="row.span.status === 'interrupted'" variant="outline" class="h-4 shrink-0 px-1.5 text-[10px]">
              中断
            </Badge>
          </span>

          <span class="relative block h-2.5 w-full">
            <span
              class="absolute inset-y-0 rounded-[3px]"
              :class="KIND_BAR[row.span.kind]"
              :style="{ left: `${row.offset}%`, width: `${row.width}%` }"
            />
          </span>

          <span class="text-muted-foreground text-right font-mono text-xs tabular-nums">
            {{ formatDuration(row.durationMs) }}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="top">
        {{ SPAN_KIND_LABELS[row.span.kind] }} · {{ row.span.name }} · {{ formatDuration(row.durationMs) }}
        <template v-if="isFailure(row.span)">
          <br>失败：{{ errorLine(row.span.error) }}
        </template>
        <template v-else-if="row.span.status === 'interrupted'">
          <br>未收到结束事件；耗时截至最后一条记录
        </template>
      </TooltipContent>
    </Tooltip>
  </div>
</template>
