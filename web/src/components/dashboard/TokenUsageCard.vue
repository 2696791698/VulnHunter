<script setup lang="ts">
import type { UsageTotals } from '@/lib/types'
import {
  ArrowDownToLineIcon,
  ArrowUpFromLineIcon,
  CircleGaugeIcon,
  CoinsIcon,
  FilePlusIcon,
  ZapIcon,
} from '@lucide/vue'
import { computed } from 'vue'
import { Card, CardContent } from '@/components/ui/card'
import { Item, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Progress } from '@/components/ui/progress'
import { NO_DATA, formatCompact, formatCount } from '@/lib/format'

const props = defineProps<{
  totals: UsageTotals | null
}>()

interface Tile {
  key: string
  label: string
  icon: object
  value: string
  /** Set only for the hit-rate tile; null means "not measurable". */
  progress?: number | null
}

const tiles = computed<Tile[]>(() => {
  const totals = props.totals
  // No totals means nothing has run yet, and every figure in this card is a
  // count — so the absence is a real 0, not an unknown. (Latency and duration
  // elsewhere keep NO_DATA: a 0 there would be a fabricated measurement.)
  if (!totals) {
    return [
      { key: 'input', label: '输入', icon: ArrowDownToLineIcon, value: '0' },
      { key: 'output', label: '输出', icon: ArrowUpFromLineIcon, value: '0' },
      { key: 'create', label: '缓存创建', icon: FilePlusIcon, value: '0' },
      { key: 'read', label: '缓存命中', icon: ZapIcon, value: '0' },
      { key: 'rate', label: '缓存命中率', icon: CircleGaugeIcon, value: '0%', progress: 0 },
    ]
  }

  return [
    { key: 'input', label: '输入', icon: ArrowDownToLineIcon, value: formatCompact(totals.newInputTokens) },
    { key: 'output', label: '输出', icon: ArrowUpFromLineIcon, value: formatCompact(totals.outputTokens) },
    // `null` on the wire means the provider reported no cache fields at all.
    // These two read as 0 rather than 没有数据; the hit rate below does not,
    // because a 0% there would look like a measurement.
    { key: 'create', label: '缓存创建', icon: FilePlusIcon, value: formatCompact(totals.cacheCreationTokens ?? 0) },
    { key: 'read', label: '缓存命中', icon: ZapIcon, value: formatCompact(totals.cacheReadTokens ?? 0) },
    {
      key: 'rate',
      label: '缓存命中率',
      icon: CircleGaugeIcon,
      value: totals.cacheHitRate === null ? NO_DATA : `${totals.cacheHitRate}%`,
      progress: totals.cacheHitRate,
    },
  ]
})
</script>

<template>
  <Card>
    <CardContent class="flex flex-col gap-5">
      <div class="flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
        <div class="flex items-start gap-3">
          <div class="bg-muted text-muted-foreground grid size-10 shrink-0 place-items-center rounded-lg">
            <CoinsIcon />
          </div>
          <div class="flex flex-col gap-1">
            <p class="text-muted-foreground text-xs">
              总消耗的 Token 数
            </p>
            <p class="text-4xl leading-none font-semibold tabular-nums">
              {{ formatCount(totals?.totalTokens ?? 0) }}
            </p>
            <p class="text-muted-foreground text-xs">
              ≈ {{ formatCompact(totals?.totalTokens ?? 0) }}
            </p>
          </div>
        </div>

        <Item variant="outline" size="xs" class="w-fit flex-col items-start gap-1">
          <ItemContent>
            <ItemDescription class="flex items-center gap-1.5">
              <ZapIcon class="size-3.5" />
              总请求数
            </ItemDescription>
            <ItemTitle class="text-lg font-semibold tabular-nums">
              {{ formatCount(totals?.requests ?? 0) }}
            </ItemTitle>
          </ItemContent>
        </Item>
      </div>

      <div class="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Item
          v-for="tile in tiles"
          :key="tile.key"
          variant="outline"
          size="xs"
          class="flex-col items-start gap-1.5"
        >
          <ItemContent>
            <ItemDescription class="flex items-center gap-1.5">
              <component :is="tile.icon" class="size-3.5 shrink-0" />
              {{ tile.label }}
            </ItemDescription>
            <ItemTitle class="text-lg font-semibold tabular-nums">
              {{ tile.value }}
            </ItemTitle>
            <Progress
              v-if="tile.progress !== undefined"
              :model-value="tile.progress ?? 0"
              class="mt-1 h-1.5"
            />
          </ItemContent>
        </Item>
      </div>
    </CardContent>
  </Card>
</template>
