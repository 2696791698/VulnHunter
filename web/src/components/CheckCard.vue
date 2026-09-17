<script setup lang="ts">
import type { CheckResult } from '@/lib/types'
import { ArrowRightIcon, TriangleAlertIcon } from '@lucide/vue'
import { computed } from 'vue'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { checkIcon } from '@/lib/check-icons'
import { formatLatency, orNoData } from '@/lib/format'
import StatusBadge from './StatusBadge.vue'

const props = defineProps<{ check: CheckResult }>()
const emit = defineEmits<{ open: [check: CheckResult] }>()

const icon = computed(() => checkIcon(props.check.icon))
</script>

<template>
  <Card>
    <CardHeader>
      <div class="flex min-w-0 items-center gap-2.5">
        <div class="bg-muted text-muted-foreground grid size-8 shrink-0 place-items-center rounded-md">
          <component :is="icon" />
        </div>
        <div class="min-w-0">
          <CardTitle>{{ check.name }}</CardTitle>
          <CardDescription>{{ check.transportLabel }}</CardDescription>
        </div>
      </div>
      <CardAction>
        <StatusBadge :state="check.state" />
      </CardAction>
    </CardHeader>

    <CardContent class="flex flex-col gap-3 pt-1">
      <p class="text-muted-foreground text-sm">
        {{ check.description }}
      </p>

      <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5 text-xs">
        <dt class="text-muted-foreground">
          连接目标
        </dt>
        <dd class="truncate font-mono">
          {{ orNoData(check.target) }}
        </dd>

        <dt class="text-muted-foreground">
          耗时
        </dt>
        <dd class="font-mono tabular-nums">
          {{ formatLatency(check.latencyMs) }}
        </dd>

        <template v-if="check.requires.length">
          <dt class="text-muted-foreground">
            依赖变量
          </dt>
          <dd class="font-mono">
            {{ check.requires.join(' · ') }}
          </dd>
        </template>
      </dl>

      <Alert v-if="check.state === 'fail'" variant="destructive">
        <TriangleAlertIcon />
        <AlertTitle>连接失败</AlertTitle>
        <AlertDescription class="break-words">
          {{ check.message }}
        </AlertDescription>
      </Alert>
    </CardContent>

    <CardFooter class="justify-end border-t-0 bg-transparent">
      <Button variant="ghost" size="sm" @click="emit('open', check)">
        查看详情
        <ArrowRightIcon data-icon="inline-end" />
      </Button>
    </CardFooter>
  </Card>
</template>
