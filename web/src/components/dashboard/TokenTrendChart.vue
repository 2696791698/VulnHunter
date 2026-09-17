<script setup lang="ts">
import type { ChartConfig } from '@/components/ui/chart'
import type { UsageBucket, UsageInterval } from '@/lib/types'
import { VisArea, VisAxis, VisCrosshair, VisScatter, VisTooltip, VisXYContainer } from '@unovis/vue'
import { ChartAreaIcon } from '@lucide/vue'
import { computed, ref, useId } from 'vue'
import { usePlotWidth } from '@/composables/usePlotWidth'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { ChartContainer, ChartLegendContent, componentToString } from '@/components/ui/chart'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { NO_DATA, formatDateTime, formatTokens } from '@/lib/format'
import TokenUsageTooltip from './TokenUsageTooltip.vue'

const props = defineProps<{
  buckets: UsageBucket[]
  interval: string
  intervals: UsageInterval[]
}>()

const emit = defineEmits<{ 'update:interval': [value: string] }>()

/**
 * Series order, which is also the row order in the legend and the tooltip.
 *
 * The four bands are a breakdown of one total — they sum to it — but each is
 * drawn as its own area, at its own value. Stacking asks for a single `VisArea`
 * carrying several accessors (`VisArea` turns stacking on exactly when `y` is an
 * array), which puts every band's edge at the running sum beneath it, so a small
 * band above a large one reads as the larger figure: 输入 sits below 缓存命中 in
 * the tooltip yet was drawn above it. One area per band keeps every series at
 * the number its own row reports; the price is that nothing is as tall as the
 * total any more.
 *
 * The lines keep Unovis's default `MonotoneX` curve. A `natural` spline passes
 * through the points but overshoots between them — on this data it drew peaks
 * at roughly twice the measured value, which is worse than not being smooth.
 */
const BANDS = [
  { key: 'cacheCreationTokens', label: '缓存创建' },
  { key: 'cacheReadTokens', label: '缓存命中' },
  { key: 'newInputTokens', label: '输入' },
  { key: 'outputTokens', label: '输出' },
] as const

const RANGES = [
  { value: '1d', label: '近 24 小时', hours: 24 },
  { value: '7d', label: '近 7 天', hours: 24 * 7 },
  { value: 'all', label: '全部', hours: null },
] as const

const range = ref<string>('7d')

const chartConfig = computed(() => {
  const config: ChartConfig = {}
  BANDS.forEach((band, index) => {
    config[band.key] = { label: band.label, color: `var(--series-${index + 1})` }
  })
  return config
})

/**
 * One accessor and one colour per band, in `BANDS` order.
 *
 * Unovis lines a colour array up with the accessor array, and a colour written
 * as `var(--color-<key>)` resolves to what this chart's own `chartConfig`
 * declared (`ChartStyle` derives those onto the container), so the series
 * colours stay defined in one place. A band the provider did not report is
 * `null` on the wire and counted as 0, here and in the tooltip alike.
 */
const seriesY = BANDS.map(band => (column: Column) => Number(column.bucket[band.key] ?? 0))
const seriesColors = BANDS.map(band => `var(--color-${band.key})`)

/** Gradient ids are document-global; `useId` keeps them unique per instance. */
const uid = useId()
const gradientId = (key: string) => `token-band-${uid}-${key}`

/**
 * The gradient fills, handed to Unovis as raw SVG.
 *
 * Unovis paints an area straight from `color`, so it has no gradient support of
 * its own — but its container will parse an arbitrary fragment into a `<defs>`
 * of its own (`svgDefs`), which means the gradients can sit in the same `<svg>`
 * as the paths referencing them.
 *
 * The stops read `var(--color-<key>)` rather than a colour of our own: shadcn's
 * `ChartStyle` derives those from this component's `chartConfig` and declares
 * them on the chart container, so the series colours stay defined in one place.
 *
 * The gradient box is the area's own bounding box, so each band fades over its
 * own height instead of the plot's: the tall 缓存命中 band fades the full height
 * of the chart, while a short 输出 band stays near its top stop.
 */
const svgDefs = BANDS.map(band => `
    <linearGradient id="${gradientId(band.key)}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="5%" stop-color="var(--color-${band.key})" stop-opacity="0.8" />
      <stop offset="95%" stop-color="var(--color-${band.key})" stop-opacity="0.1" />
    </linearGradient>`).join('')

/**
 * Fills and top-edge strokes, in the same order as `seriesY`.
 *
 * The trailing colour in each fill is SVG's paint fallback: `url(#…) <color>`
 * means "use this gradient, or this colour if it does not resolve". Without it
 * an unresolved reference paints nothing at all, which is a silent, invisible
 * failure rather than an ugly one.
 */
const areaFills = BANDS.map(band => `url(#${gradientId(band.key)}) var(--color-${band.key})`)

/**
 * The hover readout, rendered once per hovered bucket.
 *
 * `componentToString` turns the Vue component into the HTML string the tooltip
 * wants, so the markup — and the labels and the series colours, which it reads
 * off this chart's own config — stay in a `.vue` file instead of a template
 * string. Because the readout is the only place a per-bucket value is ever
 * shown, the crosshair has to work from anywhere over the plot: `false` there
 * disables Unovis's "hide when the pointer is more than 100px from a datum"
 * rule, which would otherwise blank the tooltip between two distant buckets.
 * Spell that prop in camelCase — the Vue wrapper forwards attributes to the
 * config untyped, so a kebab-case one never reaches it.
 */
const tooltipTemplate = componentToString(chartConfig.value, TokenUsageTooltip)

interface Column {
  bucket: UsageBucket
  index: number
}

const columns = computed<Column[]>(() => {
  const selected = RANGES.find(item => item.value === range.value)
  const now = Date.now()
  // Bounded on both sides: "the last N hours" ends now, and a bucket dated
  // ahead of the reader's clock is not part of any past window.
  const from = selected?.hours ? now - selected.hours * 60 * 60 * 1000 : null

  const visible = from === null
    ? props.buckets
    : props.buckets.filter((bucket) => {
        const at = Date.parse(bucket.key)
        return at >= from && at <= now
      })

  return visible.map((bucket, index) => ({ bucket, index }))
})

const x = (column: Column) => column.index

const tickValues = computed(() => {
  const last = columns.value.length - 1
  if (last <= 3)
    return columns.value.map(column => column.index)
  const step = last / 3
  return [...new Set([0, 1, 2, 3].map(i => Math.round(i * step)))]
})

/** Buckets arrive as UTC hours; render them where the reader is. */
function tickLabel(index: number): string {
  const key = columns.value[Math.round(index)]?.bucket.key
  return key ? formatDateTime(key) : ''
}

const rangeLabel = computed(
  () => RANGES.find(item => item.value === range.value)?.label ?? '全部',
)

/** The bucket-size options are the bridge's; no copy is kept here. */
const intervalLabel = computed(
  () => props.intervals.find(item => item.value === props.interval)?.label ?? '每格',
)

const { plotRef, plotWidth } = usePlotWidth()
</script>

<template>
  <Card class="@container/card">
    <CardHeader>
      <CardTitle>使用趋势</CardTitle>
      <CardDescription>
        {{ rangeLabel }}内共 {{ columns.length }} 个区间，每格 {{ intervalLabel }}，各条线为该项自身的数值，不做累加。缓存字段由模型服务商上报，未上报时按 0 处理。
      </CardDescription>
      <CardAction>
        <div class="flex items-center gap-2">
          <Select
            :model-value="interval"
            @update:model-value="(value) => value && emit('update:interval', String(value))"
          >
            <SelectTrigger size="sm" aria-label="选择时间间隔" class="w-28">
              <SelectValue :placeholder="intervalLabel" />
            </SelectTrigger>
            <SelectContent class="rounded-xl">
              <SelectItem v-for="item in intervals" :key="item.value" :value="item.value" class="rounded-lg">
                {{ item.label }}
              </SelectItem>
            </SelectContent>
          </Select>

          <Select :model-value="range" @update:model-value="(value) => value && (range = String(value))">
            <SelectTrigger size="sm" aria-label="选择时间范围" class="w-32">
              <SelectValue :placeholder="rangeLabel" />
            </SelectTrigger>
            <SelectContent class="rounded-xl">
              <SelectItem v-for="item in RANGES" :key="item.value" :value="item.value" class="rounded-lg">
                {{ item.label }}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardAction>
    </CardHeader>

    <CardContent class="px-2 pt-4 sm:px-6 sm:pt-6">
      <Empty v-if="columns.length === 0" class="min-h-[280px]">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <ChartAreaIcon />
          </EmptyMedia>
          <EmptyTitle>{{ NO_DATA }}</EmptyTitle>
          <EmptyDescription>还没有 agent 运行记录，跑一次审计后这里会出现 token 消耗趋势。</EmptyDescription>
        </EmptyHeader>
      </Empty>

      <div v-else ref="plotRef" class="relative">
        <ChartContainer v-if="plotWidth > 0" :config="chartConfig" cursor class="aspect-auto h-[300px] w-full">
          <VisXYContainer
            :data="columns"
            :svg-defs="svgDefs"
            :margin="{ top: 8, right: 16, bottom: 4, left: 56 }"
            :duration="0"
          >
            <!-- One area per band, each with a single accessor, which is what
                 keeps them unstacked (`VisArea` stacks exactly when `y` is an
                 array). Painted in list order, so the smallest band ends up on
                 top of the larger ones it sits inside. -->
            <VisArea
              v-for="(band, index) in BANDS"
              :key="band.key"
              :x="x"
              :y="seriesY[index]"
              :baseline="0"
              :color="areaFills[index]"
              :opacity="0.4"
              line
              :line-width="2"
              :line-color="seriesColors[index]"
            />
            <!-- A marker per series, but only when the chart has nothing else to
                 show: an area needs two points to draw at all, so a lone bucket
                 would otherwise render as an empty plot. The moment there are
                 two buckets the top edges already say it. -->
            <template v-if="columns.length < 2">
              <VisScatter
                v-for="(band, index) in BANDS"
                :key="band.key"
                :x="x"
                :y="seriesY[index]"
                :size="9"
                :color="seriesColors[index]"
              />
            </template>
            <VisAxis
              type="x"
              :x="x"
              :tick-values="tickValues"
              :tick-format="(index: number) => tickLabel(index)"
              :grid-line="false"
              :tick-line="false"
            />
            <VisAxis
              type="y"
              :num-ticks="4"
              :tick-format="(tick: number) => formatTokens(tick)"
              :domain-line="false"
            />
            <VisCrosshair
              :x="x"
              :template="tooltipTemplate"
              :hideWhenFarFromPointer="false"
            />
            <VisTooltip />
          </VisXYContainer>
          <ChartLegendContent />
        </ChartContainer>
      </div>
    </CardContent>
  </Card>
</template>
