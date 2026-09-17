<script setup lang="ts">
import type { Span } from '@/lib/traces'
import { CircleAlertIcon, CircleCheckIcon, LoaderIcon, TriangleAlertIcon } from '@lucide/vue'
import { computed } from 'vue'
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
import { formatClock, formatDuration, formatTokens } from '@/lib/format'
import { SPAN_KIND_LABELS, SPAN_STATUS_LABELS } from '@/lib/traces'

const props = defineProps<{
  span: Span | null
  open: boolean
}>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const open = computed({
  get: () => props.open,
  set: value => emit('update:open', value),
})

const duration = computed(() => {
  if (!props.span)
    return null
  const from = Date.parse(props.span.startedAt)
  const to = props.span.endedAt ? Date.parse(props.span.endedAt) : Date.now()
  return to - from
})

const STATUS_TONE = {
  ok: 'text-status-good',
  error: 'text-status-critical',
  running: 'text-muted-foreground',
} as const

const STATUS_ICON = {
  ok: CircleCheckIcon,
  error: CircleAlertIcon,
  running: LoaderIcon,
} as const

function pretty(value: unknown): string {
  if (value === null || value === undefined)
    return '—'
  try {
    return JSON.stringify(value, null, 2)
  }
  catch {
    return String(value)
  }
}
</script>

<template>
  <Sheet v-model:open="open">
    <SheetContent class="w-full gap-0 sm:max-w-lg">
      <template v-if="span">
        <SheetHeader>
          <SheetTitle class="truncate">
            {{ span.name }}
          </SheetTitle>
          <SheetDescription>
            {{ SPAN_KIND_LABELS[span.kind] }} · {{ span.id }}
          </SheetDescription>
        </SheetHeader>

        <Separator />

        <div class="flex min-h-0 flex-1 flex-col gap-4 p-4">
          <div class="flex items-center justify-between">
            <span class="text-muted-foreground text-sm">状态</span>
            <Badge variant="outline">
              <component :is="STATUS_ICON[span.status]" :class="STATUS_TONE[span.status]" />
              {{ SPAN_STATUS_LABELS[span.status] }}
            </Badge>
          </div>

          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt class="text-muted-foreground">
              耗时
            </dt>
            <dd class="font-mono text-xs tabular-nums">
              {{ formatDuration(duration) }}
            </dd>

            <dt class="text-muted-foreground">
              开始时间
            </dt>
            <dd class="font-mono text-xs tabular-nums">
              {{ formatClock(span.startedAt) }}
            </dd>

            <template v-if="span.model">
              <dt class="text-muted-foreground">
                模型
              </dt>
              <dd class="font-mono text-xs">
                {{ span.model }}
              </dd>
            </template>

            <template v-if="span.usage">
              <dt class="text-muted-foreground">
                Token
              </dt>
              <dd class="font-mono text-xs tabular-nums">
                输入 {{ formatTokens(span.usage.inputTokens) }} · 输出 {{ formatTokens(span.usage.outputTokens) }} · 合计 {{ formatTokens(span.usage.totalTokens) }}
              </dd>
            </template>
          </dl>

          <Alert v-if="span.error" variant="destructive">
            <TriangleAlertIcon />
            <AlertTitle>调用失败</AlertTitle>
            <AlertDescription class="break-words">
              {{ span.error }}
            </AlertDescription>
          </Alert>

          <div class="flex min-h-0 flex-1 flex-col gap-2">
            <h3 class="text-sm font-medium">
              输入
            </h3>
            <ScrollArea class="bg-muted max-h-56 rounded-lg">
              <pre class="p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">{{ pretty(span.inputs) }}</pre>
            </ScrollArea>
          </div>

          <div class="flex min-h-0 flex-1 flex-col gap-2">
            <h3 class="text-sm font-medium">
              输出
            </h3>
            <ScrollArea class="bg-muted max-h-56 rounded-lg">
              <pre class="p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">{{ pretty(span.outputs) }}</pre>
            </ScrollArea>
          </div>
        </div>

        <SheetFooter>
          <Button variant="outline" @click="open = false">
            关闭
          </Button>
        </SheetFooter>
      </template>
    </SheetContent>
  </Sheet>
</template>
