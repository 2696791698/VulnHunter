<script setup lang="ts">
import type { ChartConfig } from '@/components/ui/chart'
import type { UsageBucket } from '@/lib/types'
import { computed } from 'vue'
import { formatCount, formatDateTime } from '@/lib/format'

/**
 * The hover readout for `TokenTrendChart`, rendered by unovis's tooltip through
 * `componentToString`.
 *
 * Rows come from the chart's own `config`, in its insertion order — the config
 * is built from the band list, so the tooltip, the legend and the stack can
 * never drift apart. A band the provider did not report is `null` on the wire
 * and prints as 0 here, matching how the chart plots it.
 */
const props = defineProps<{
  /** The crosshair hands over the data item it snapped to: one `Column`. */
  payload?: { bucket: UsageBucket }
  config?: ChartConfig
  /**
   * The snapped X, passed by `componentToString`. Unused — the bucket carries
   * its own timestamp — but declared so it is consumed as a prop rather than
   * landing on the box as a stray HTML attribute.
   */
  x?: number | Date
}>()

const bucket = computed(() => props.payload?.bucket ?? null)

const rows = computed(() =>
  Object.entries(props.config ?? {}).map(([key, item]) => {
    const value = (bucket.value as Record<string, unknown> | null)?.[key]
    return {
      key,
      label: item.label ?? key,
      color: item.color,
      /** Null is "the provider did not report it"; the template prints 0. */
      value: typeof value === 'number' ? value : null,
    }
  }),
)
</script>

<template>
  <div
    class="border-border/50 bg-background grid min-w-40 gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs shadow-xl"
  >
    <div v-if="bucket" class="font-medium">
      {{ formatDateTime(bucket.key) }}
    </div>

    <div class="grid gap-1">
      <div v-for="row in rows" :key="row.key" class="flex items-center gap-2">
        <span
          class="h-2.5 w-1 shrink-0 rounded-full"
          :style="{ backgroundColor: row.color }"
          aria-hidden="true"
        />
        <span class="text-muted-foreground flex-1">{{ row.label }}</span>
        <span class="text-foreground font-mono font-medium tabular-nums">
          {{ formatCount(row.value ?? 0) }}
        </span>
      </div>
    </div>

    <div
      v-if="bucket"
      class="border-border/60 flex items-center gap-2 border-t pt-1.5"
    >
      <span class="text-muted-foreground flex-1">合计</span>
      <span class="text-foreground font-mono font-medium tabular-nums">
        {{ formatCount(bucket.totalTokens) }}
      </span>
    </div>
  </div>
</template>
