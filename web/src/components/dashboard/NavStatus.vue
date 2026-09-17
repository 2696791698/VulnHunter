<script setup lang="ts">
import type { Source } from '@/lib/types'
import { DatabaseZapIcon, PlugZapIcon } from '@lucide/vue'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { SOURCE_LABELS } from '@/lib/format'
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'

defineProps<{
  /** Where the data came from — drives both the icon and the label. */
  source: Source
  detail: string
}>()
</script>

<template>
  <SidebarMenu>
    <SidebarMenuItem>
      <SidebarMenuButton as="div" size="lg" class="cursor-default">
        <Avatar class="size-8 rounded-lg">
          <AvatarFallback class="rounded-lg">
            <DatabaseZapIcon v-if="source === 'live'" />
            <PlugZapIcon v-else />
          </AvatarFallback>
        </Avatar>
        <div class="grid flex-1 text-left text-sm leading-tight">
          <span class="truncate font-medium">{{ SOURCE_LABELS[source] }}</span>
          <span class="text-muted-foreground truncate text-xs">{{ detail }}</span>
        </div>
      </SidebarMenuButton>
    </SidebarMenuItem>
  </SidebarMenu>
</template>
