<script setup lang="ts">
import type { CheckResult } from '@/lib/types'
import { RouterLink } from 'vue-router'
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { STATE_LABELS, formatLatency } from '@/lib/format'

defineProps<{ checks: CheckResult[] }>()

/* The name next to the dot is the label, so the colour is only a secondary cue. */
const DOTS: Record<CheckResult['state'], string> = {
  pass: 'bg-status-good',
  fail: 'bg-status-critical',
  running: 'bg-muted-foreground animate-pulse',
  idle: 'bg-muted-foreground/40',
}
</script>

<template>
  <SidebarGroup class="group-data-[collapsible=icon]:hidden">
    <SidebarGroupLabel>依赖项</SidebarGroupLabel>
    <SidebarGroupContent>
      <SidebarMenu>
        <SidebarMenuItem v-for="check in checks" :key="check.id">
          <SidebarMenuButton
            as-child
            size="sm"
            :tooltip="`${check.name} · ${STATE_LABELS[check.state]}`"
          >
            <RouterLink :to="{ name: 'env-check', hash: `#check-${check.id}` }">
              <span class="size-2 shrink-0 rounded-full" :class="DOTS[check.state]" aria-hidden="true" />
              <span>{{ check.name }}</span>
            </RouterLink>
          </SidebarMenuButton>
          <SidebarMenuBadge>
            {{ check.latencyMs === null ? STATE_LABELS[check.state] : formatLatency(check.latencyMs) }}
          </SidebarMenuBadge>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroupContent>
  </SidebarGroup>
</template>
