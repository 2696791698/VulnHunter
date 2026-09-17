<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { RouterView } from 'vue-router'
import { toast } from 'vue-sonner'
import AppSidebar from '@/components/dashboard/AppSidebar.vue'
import SiteHeader from '@/components/dashboard/SiteHeader.vue'
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { useEnvironment } from '@/composables/useEnvironment'
import { bridgeStartCommand } from '@/lib/api'
import { NO_DATA, formatLatency, formatRelative } from '@/lib/format'

const {
  running,
  checks,
  source,
  lastRun,
  load,
} = useEnvironment()

const detail = computed(() => {
  if (running.value)
    return '正在检测…'
  if (!lastRun.value)
    return NO_DATA
  return `${formatRelative(lastRun.value.startedAt)} · 用时 ${formatLatency(lastRun.value.durationMs)}`
})

/**
 * Copies the command that starts a bridge. The command comes from the bridge
 * itself when one is reachable, and from the documented default otherwise —
 * the unreachable case being exactly when this is useful.
 */
async function copyBridgeCommand() {
  const command = await bridgeStartCommand()

  try {
    await navigator.clipboard.writeText(command)
    toast.success('已复制桥接服务启动命令', { description: command })
  }
  catch {
    toast.error('复制失败，请手动执行', { description: command })
  }
}

onMounted(load)
</script>

<template>
  <TooltipProvider>
    <SidebarProvider
      :style="{
        '--sidebar-width': 'calc(var(--spacing) * 72)',
        '--header-height': 'calc(var(--spacing) * 12)',
      }"
    >
      <AppSidebar
        :checks="checks"
        :source="source"
        :detail="detail"
        @copy-command="copyBridgeCommand"
      />

      <SidebarInset>
        <SiteHeader :source="source" :detail="detail" />

        <div class="flex flex-1 flex-col">
          <div class="@container/main flex flex-1 flex-col gap-2">
            <div class="flex flex-1 flex-col gap-4 py-4 md:gap-6 md:py-6">
              <RouterView />
            </div>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>

    <Toaster position="bottom-right" />
  </TooltipProvider>
</template>
