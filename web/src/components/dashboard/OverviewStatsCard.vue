<script setup lang="ts">
import type { CheckResult } from '@/lib/types'
import { ActivityIcon } from '@lucide/vue'
import { computed } from 'vue'
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Item, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { NO_DATA, formatLatency } from '@/lib/format'

const props = defineProps<{ checks: CheckResult[] }>()

/** Only a check that has actually been measured counts towards the summary. */
const measured = computed(() => props.checks.filter(
  check => check.state === 'pass' || check.state === 'fail',
))

/** The series palette is assigned in the backend's check order, not by rank. */
function seriesColor(index: number): string {
  return `var(--series-${(index % 5) + 1})`
}

const EMPTY_TILES = [
  { key: 'rate', label: '通过率', value: NO_DATA, hint: NO_DATA },
  { key: 'passed', label: '通过', value: NO_DATA, hint: NO_DATA },
  { key: 'failed', label: '失败', value: NO_DATA, hint: NO_DATA },
  { key: 'total', label: '本次耗时', value: NO_DATA, hint: NO_DATA },
]

const tiles = computed(() => {
  const results = measured.value
  if (results.length === 0)
    return EMPTY_TILES

  const passed = results.filter(result => result.state === 'pass').length
  const failed = results.filter(result => result.state === 'fail').length
  const failing = results.filter(result => result.state === 'fail').map(result => result.name)
  const rate = Math.round((passed / results.length) * 100)
  const total = results.reduce((sum, result) => sum + (result.latencyMs ?? 0), 0)

  return [
    { key: 'rate', label: '通过率', value: `${rate}%`, hint: `共 ${results.length} 项` },
    { key: 'passed', label: '通过', value: String(passed), hint: '连接与调用均成功' },
    {
      key: 'failed',
      label: '失败',
      value: String(failed),
      hint: failing.length === 0 ? '没有需要排查的依赖' : `待排查：${failing.join('、')}`,
    },
    { key: 'total', label: '本次耗时', value: formatLatency(total), hint: `${results.length} 项检测累计` },
  ]
})

/** Composition of the reading, one segment per check. */
const composition = computed(() => {
  const parts = props.checks
    .map((result, index) => ({ result, index }))
    .filter(({ result }) => (result.latencyMs ?? 0) > 0)

  const total = parts.reduce((sum, { result }) => sum + (result.latencyMs ?? 0), 0)
  if (total === 0)
    return { segments: [], totalLabel: NO_DATA }

  return {
    totalLabel: formatLatency(total),
    segments: parts.map(({ result, index }) => ({
      id: result.id,
      name: result.name,
      color: seriesColor(index),
      percent: ((result.latencyMs ?? 0) / total) * 100,
      share: `${(((result.latencyMs ?? 0) / total) * 100).toFixed(1)}%`,
    })),
  }
})
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle class="flex items-center gap-2">
        <ActivityIcon class="text-muted-foreground" />
        检测概览
      </CardTitle>
    </CardHeader>

    <CardContent class="flex flex-col gap-5">
      <div class="divide-border grid grid-cols-2 divide-x rounded-lg border sm:grid-cols-4">
        <Item
          v-for="tile in tiles"
          :key="tile.key"
          size="xs"
          variant="default"
          class="flex-col items-start rounded-none border-0 py-3 hover:bg-transparent"
        >
          <ItemContent>
            <ItemDescription>{{ tile.label }}</ItemDescription>
            <ItemTitle class="text-2xl font-semibold tabular-nums">
              {{ tile.value }}
            </ItemTitle>
            <ItemDescription>{{ tile.hint }}</ItemDescription>
          </ItemContent>
        </Item>
      </div>

      <div class="flex flex-col gap-3">
        <div class="flex items-baseline justify-between">
          <span class="text-muted-foreground text-xs">耗时构成</span>
          <span class="font-mono text-xs tabular-nums">{{ composition.totalLabel }}</span>
        </div>

        <div v-if="composition.segments.length" class="flex h-2.5 w-full gap-[2px]">
          <div
            v-for="segment in composition.segments"
            :key="segment.id"
            class="h-full min-w-[2px]"
            :style="{ width: `${segment.percent}%`, backgroundColor: segment.color }"
          />
        </div>
        <div v-else class="bg-muted h-2.5 w-full rounded-[4px]" />

        <ul class="flex flex-wrap items-center gap-x-4 gap-y-1.5">
          <li
            v-for="segment in composition.segments"
            :key="segment.id"
            class="text-muted-foreground flex items-center gap-1.5 text-xs"
          >
            <span class="size-2.5 shrink-0 rounded-sm" :style="{ backgroundColor: segment.color }" />
            {{ segment.name }} {{ segment.share }}
          </li>
          <li v-if="!composition.segments.length" class="text-muted-foreground text-xs">
            {{ NO_DATA }}
          </li>
        </ul>
      </div>
    </CardContent>
  </Card>
</template>
