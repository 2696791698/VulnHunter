<script setup lang="ts">
import type { CheckResult } from '@/lib/types'
import { computed } from 'vue'
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
import { formatLatency, orNoData } from '@/lib/format'
import StatusBadge from './StatusBadge.vue'

const props = defineProps<{
  check: CheckResult | null
  open: boolean
}>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()

const open = computed({
  get: () => props.open,
  set: value => emit('update:open', value),
})
</script>

<template>
  <Sheet v-model:open="open">
    <SheetContent class="w-full gap-0 sm:max-w-md">
      <template v-if="check">
        <SheetHeader>
          <SheetTitle>{{ check.name }}</SheetTitle>
          <SheetDescription>
            {{ check.transportLabel }} · {{ check.description }}
          </SheetDescription>
        </SheetHeader>

        <Separator />

        <div class="flex min-h-0 flex-1 flex-col gap-4 p-4">
          <div class="flex items-center justify-between">
            <span class="text-muted-foreground text-sm">当前状态</span>
            <StatusBadge :state="check.state" />
          </div>

          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt class="text-muted-foreground">
              连接目标
            </dt>
            <dd class="truncate font-mono text-xs">
              {{ orNoData(check.target) }}
            </dd>

            <dt class="text-muted-foreground">
              耗时
            </dt>
            <dd class="font-mono text-xs tabular-nums">
              {{ formatLatency(check.latencyMs) }}
            </dd>

            <template v-if="check.requires.length">
              <dt class="text-muted-foreground">
                依赖变量
              </dt>
              <dd class="font-mono text-xs">
                {{ check.requires.join(' · ') }}
              </dd>
            </template>
          </dl>

          <div class="flex min-h-0 flex-1 flex-col gap-2">
            <h3 class="text-sm font-medium">
              原始输出
            </h3>
            <ScrollArea class="bg-muted min-h-0 flex-1 rounded-lg">
              <pre class="p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">{{ check.log.join('\n') }}</pre>
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
