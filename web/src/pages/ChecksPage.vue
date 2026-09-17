<script setup lang="ts">
import type { CheckResult } from '@/lib/types'
import { PlugZapIcon, RefreshCwIcon } from '@lucide/vue'
import { nextTick, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import CheckCard from '@/components/CheckCard.vue'
import { Button } from '@/components/ui/button'
import CheckDetailsSheet from '@/components/CheckDetailsSheet.vue'
import OverviewStatsCard from '@/components/dashboard/OverviewStatsCard.vue'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { useEnvironment } from '@/composables/useEnvironment'
import { NO_DATA } from '@/lib/format'

const { checks, reading, loading, running, lastRun, run } = useEnvironment()
const route = useRoute()

const selected = ref<CheckResult | null>(null)
const sheetOpen = ref(false)

function openDetails(check: CheckResult) {
  selected.value = check
  sheetOpen.value = true
}

/** Deep links like /env-check#check-codeql land on the matching card. */
function scrollToHash() {
  const id = route.hash.replace(/^#/, '')
  if (!id)
    return
  nextTick(() => document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'center' }))
}

onMounted(scrollToHash)
watch(() => route.hash, scrollToHash)
</script>

<template>
  <section class="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
    <div class="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div class="flex flex-col gap-1">
        <h2 class="text-lg font-semibold">
          环境检查
        </h2>
        <p class="text-muted-foreground text-sm">
          每张卡片对应 check_environment.py 中的一项检查，点击可查看原始输出。
          <template v-if="lastRun">
            本次检测于 {{ new Date(lastRun.startedAt).toLocaleString('zh-CN', { hour12: false }) }}。
          </template>
        </p>
      </div>

      <Button size="sm" :disabled="running" @click="run">
        <Spinner v-if="running" data-icon="inline-start" />
        <RefreshCwIcon v-else data-icon="inline-start" />
        {{ running ? '检测中…' : '重新检测' }}
      </Button>
    </div>

    <OverviewStatsCard v-if="!loading" :checks="reading" />

    <div v-if="loading" class="grid gap-4 @xl/main:grid-cols-2 @5xl/main:grid-cols-3">
      <Skeleton v-for="n in 3" :key="n" class="h-64 rounded-xl" />
    </div>

    <Empty v-else-if="checks.length === 0" class="border-dashed">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <PlugZapIcon />
        </EmptyMedia>
        <EmptyTitle>{{ NO_DATA }}</EmptyTitle>
        <EmptyDescription>无法连接桥接服务，请确认 web/server/main.py 正在运行。</EmptyDescription>
      </EmptyHeader>
    </Empty>

    <div v-else class="grid gap-4 @xl/main:grid-cols-2 @5xl/main:grid-cols-3">
      <CheckCard
        v-for="check in checks"
        :id="`check-${check.id}`"
        :key="check.id"
        :check="check"
        class="scroll-mt-6"
        @open="openDetails"
      />
    </div>

    <CheckDetailsSheet v-model:open="sheetOpen" :check="selected" />
  </section>
</template>
