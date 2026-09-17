<script setup lang="ts">
import type { CheckResult, Source } from '@/lib/types'
import { ShieldCheckIcon } from '@lucide/vue'
import { RouterLink } from 'vue-router'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar'
import { NAV_SECTIONS } from '@/lib/navigation'
import NavChecks from './NavChecks.vue'
import NavMain from './NavMain.vue'
import NavSecondary from './NavSecondary.vue'
import NavStatus from './NavStatus.vue'

defineProps<{
  checks: CheckResult[]
  source: Source
  detail: string
}>()

const emit = defineEmits<{ copyCommand: [] }>()
</script>

<template>
  <Sidebar variant="inset" collapsible="offcanvas">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton as-child class="data-[slot=sidebar-menu-button]:p-1.5!">
            <RouterLink to="/overview">
              <ShieldCheckIcon class="size-5!" />
              <span class="text-base font-semibold">VulnHunter</span>
            </RouterLink>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>

    <SidebarContent>
      <NavMain :items="NAV_SECTIONS" />
      <NavChecks :checks="checks" />
      <NavSecondary @copy-command="emit('copyCommand')" />
    </SidebarContent>

    <SidebarFooter>
      <NavStatus :source="source" :detail="detail" />
    </SidebarFooter>
  </Sidebar>
</template>
