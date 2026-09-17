<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import type { CheckState } from '@/lib/types'
import { CircleAlertIcon, CircleCheckIcon, CircleDashedIcon, LoaderIcon } from '@lucide/vue'
import { computed } from 'vue'
import { Badge } from '@/components/ui/badge'
import { STATE_LABELS } from '@/lib/format'

const props = defineProps<{
  state: CheckState
  class?: HTMLAttributes['class']
}>()

/* Status colour never carries the meaning on its own — every badge pairs it
 * with an icon and a text label. */
const ICONS = {
  pass: CircleCheckIcon,
  fail: CircleAlertIcon,
  running: LoaderIcon,
  idle: CircleDashedIcon,
} as const

const TONES: Record<CheckState, string> = {
  pass: 'text-status-good',
  fail: 'text-status-critical',
  running: 'text-muted-foreground animate-spin',
  idle: 'text-muted-foreground',
}

const icon = computed(() => ICONS[props.state])
</script>

<template>
  <Badge variant="outline" :class="props.class">
    <component :is="icon" :class="TONES[state]" data-icon="inline-start" />
    {{ STATE_LABELS[state] }}
  </Badge>
</template>
