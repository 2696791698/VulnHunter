<script setup lang="ts">
import type { Span, SpanKind, Trace } from '@/lib/traces'
import type { Component } from 'vue'
import { BlocksIcon, CircleAlertIcon, SparkleIcon, WrenchIcon } from '@lucide/vue'
import { computed } from 'vue'
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

  function walk(span: Span, depth: number) {
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

  for (const root of children.get(null) ?? [])
    walk(root, 0)

  return out
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

  <div v-else class="flex flex-col">
    <Tooltip v-for="row in rows" :key="row.span.id">
      <TooltipTrigger as-child>
        <button
          type="button"
          class="hover:bg-muted/60 focus-visible:ring-ring/50 grid w-full grid-cols-[minmax(8rem,14rem)_1fr_5rem] items-center gap-3 rounded-md px-2 py-1 text-left outline-none focus-visible:ring-3"
          :class="row.span.id === selectedSpanId && 'bg-muted'"
          @click="emit('select', row.span)"
        >
          <span
            class="flex min-w-0 items-center gap-1.5"
            :style="{ paddingLeft: `${row.depth * 12}px` }"
          >
            <component :is="KIND_ICON[row.span.kind]" class="size-3.5 shrink-0" :class="KIND_COLOR[row.span.kind]" />
            <span class="truncate text-xs">{{ row.span.name }}</span>
            <CircleAlertIcon v-if="row.span.status === 'error'" class="text-status-critical size-3 shrink-0" />
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
      </TooltipContent>
    </Tooltip>
  </div>
</template>
