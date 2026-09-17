<script setup lang="ts">
import { MoonIcon, SunIcon, SquareTerminalIcon } from '@lucide/vue'
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { useTheme } from '@/composables/useTheme'

const emit = defineEmits<{ copyCommand: [] }>()

const { theme, toggle } = useTheme()
</script>

<template>
  <SidebarGroup class="mt-auto">
    <SidebarGroupContent>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton tooltip="切换明暗主题" @click="toggle">
            <SunIcon v-if="theme === 'dark'" />
            <MoonIcon v-else />
            <span>{{ theme === 'dark' ? '浅色主题' : '深色主题' }}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>

        <SidebarMenuItem>
          <SidebarMenuButton tooltip="复制桥接服务命令" @click="emit('copyCommand')">
            <SquareTerminalIcon />
            <span>复制桥接命令</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroupContent>
  </SidebarGroup>
</template>
