<script setup lang="ts">
import { computed } from 'vue'
import { useVirtualList } from '@vueuse/core'
import { Button } from '@/components/ui/button'
import { formatBytes } from '@/lib/format'

const props = defineProps<{
  value: unknown
  /** The payloads are still on their way; the value is metadata only. */
  loading?: boolean
}>()

/** The pretty-printed payload, computed once per value rather than on every
 * re-render — stringifying a few megabytes in a template function is what made
 * this view stutter. */
const text = computed(() => {
  if (props.value === null || props.value === undefined)
    return ''
  try {
    return JSON.stringify(props.value, null, 2)
  }
  catch {
    return String(props.value)
  }
})

const bytes = computed(() => new Blob([text.value]).size)

/**
 * Rendered a line at a time, and long lines cut into fixed-width pieces.
 *
 * A payload is now stored whole, so this can be several megabytes; without
 * splitting, one file's worth of JSON would be a single enormous text node and
 * the browser would lay all of it out at once.
 */
const ROW_CHARS = 400

const rows = computed(() => {
  if (!text.value)
    return []
  const out: string[] = []
  for (const line of text.value.split('\n')) {
    if (line.length <= ROW_CHARS) {
      out.push(line)
      continue
    }
    for (let start = 0; start < line.length; start += ROW_CHARS)
      out.push(line.slice(start, start + ROW_CHARS))
  }
  return out
})

// Row height is fixed in CSS (`h-[18px]`) so this stays exact.
const { list, containerProps, wrapperProps } = useVirtualList(rows, {
  itemHeight: 18,
  overscan: 16,
})

function download() {
  const blob = new Blob([text.value], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'payload.json'
  link.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="flex min-h-0 flex-col gap-2">
    <div class="flex items-center gap-2">
      <slot name="label" />
      <span v-if="text" class="text-muted-foreground font-mono text-xs tabular-nums">
        {{ formatBytes(bytes) }}
      </span>
      <Button
        v-if="text"
        variant="ghost"
        size="sm"
        class="ml-auto h-6 px-2 text-xs"
        @click="download"
      >
        下载
      </Button>
    </div>

    <div
      v-bind="containerProps"
      class="bg-muted max-h-56 overflow-auto rounded-lg"
    >
      <div v-bind="wrapperProps">
        <div
          v-for="row in list"
          :key="row.index"
          class="h-[18px] font-mono text-xs leading-[18px] whitespace-pre"
        >{{ row.data === '' ? ' ' : row.data }}</div>
      </div>

      <p v-if="!text && !loading" class="text-muted-foreground p-3 text-xs">
        没有数据
      </p>
      <p v-else-if="!text && loading" class="text-muted-foreground p-3 text-xs">
        正在读取…
      </p>
    </div>
  </div>
</template>
