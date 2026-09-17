<script setup lang="ts">
import type { AuditTask } from '@/lib/types'
import {
  CircleAlertIcon,
  CircleCheckIcon,
  ClockIcon,
  GitBranchIcon,
  LoaderIcon,
  TriangleAlertIcon,
} from '@lucide/vue'
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
import { AUDIT_STATUS_LABELS, NO_DATA, elapsedLabel, formatDateTime, orNoData } from '@/lib/format'

const props = defineProps<{
  task: AuditTask | null
  open: boolean
}>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const open = computed({
  get: () => props.open,
  set: value => emit('update:open', value),
})

const TONE = {
  queued: 'text-muted-foreground',
  cloning: 'text-muted-foreground animate-pulse',
  running: 'text-muted-foreground animate-spin',
  done: 'text-status-good',
  failed: 'text-status-critical',
} as const

const STATUS_ICON = {
  queued: ClockIcon,
  cloning: GitBranchIcon,
  running: LoaderIcon,
  done: CircleCheckIcon,
  failed: CircleAlertIcon,
} as const
</script>

<template>
  <Sheet v-model:open="open">
    <SheetContent class="w-full gap-0 sm:max-w-xl">
      <template v-if="task">
        <SheetHeader>
          <SheetTitle class="truncate">
            {{ task.url }}
          </SheetTitle>
          <SheetDescription>
            commit {{ task.commit }} · {{ task.id }}
          </SheetDescription>
        </SheetHeader>

        <Separator />

        <div class="flex min-h-0 flex-1 flex-col gap-4 p-4">
          <div class="flex items-center justify-between">
            <span class="text-muted-foreground text-sm">状态</span>
            <Badge variant="outline">
              <component :is="STATUS_ICON[task.status]" :class="TONE[task.status]" />
              {{ AUDIT_STATUS_LABELS[task.status] }}
            </Badge>
          </div>

          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt class="text-muted-foreground">
              创建时间
            </dt>
            <dd class="font-mono text-xs tabular-nums">
              {{ formatDateTime(task.createdAt) }}
            </dd>

            <dt class="text-muted-foreground">
              用时
            </dt>
            <dd class="font-mono text-xs tabular-nums">
              {{ elapsedLabel(task.startedAt, task.endedAt) }}
            </dd>

            <dt class="text-muted-foreground">
              检出目录
            </dt>
            <dd class="truncate font-mono text-xs">
              {{ orNoData(task.checkout) }}
            </dd>
          </dl>

          <Alert v-if="task.error" variant="destructive">
            <TriangleAlertIcon />
            <AlertTitle>任务失败</AlertTitle>
            <AlertDescription class="break-words">
              {{ task.error }}
            </AlertDescription>
          </Alert>

          <div class="flex min-h-0 flex-1 flex-col gap-2">
            <h3 class="text-sm font-medium">
              审查结论
            </h3>
            <ScrollArea class="bg-muted min-h-0 flex-1 rounded-lg">
              <pre class="p-3 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap">{{ orNoData(task.verdict) }}</pre>
            </ScrollArea>
            <p v-if="!task.verdict && task.status !== 'failed'" class="text-muted-foreground text-xs">
              {{ NO_DATA }} —— 任务还没跑完。
            </p>
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
