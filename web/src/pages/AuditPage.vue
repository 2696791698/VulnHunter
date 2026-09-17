<script setup lang="ts">
import type { AuditTask } from '@/lib/types'
import {
  CircleAlertIcon,
  CircleCheckIcon,
  ClockIcon,
  FileSearchIcon,
  GitBranchIcon,
  LoaderIcon,
  PlayIcon,
} from '@lucide/vue'
import { computed, reactive, ref } from 'vue'
import AuditTaskSheet from '@/components/dashboard/AuditTaskSheet.vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Item, ItemContent, ItemDescription, ItemTitle } from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { useAuditTasks } from '@/composables/useAuditTasks'
import { AUDIT_STATUS_LABELS, NO_DATA, elapsedLabel, formatRelative, orNoData } from '@/lib/format'

const { tasks, loading, submit } = useAuditTasks()

const form = reactive({ url: '', commit: '' })
const submitting = ref(false)
const formError = ref<string | null>(null)

const canSubmit = computed(() =>
  form.url.trim().length > 0 && form.commit.trim().length > 0 && !submitting.value,
)

const selected = ref<AuditTask | null>(null)
const sheetOpen = ref(false)

function openTask(task: AuditTask) {
  selected.value = task
  sheetOpen.value = true
}

/**
 * The bridge owns validation, so its message is what the form reports — the
 * frontend does not keep a second copy of the rules.
 */
async function onSubmit() {
  formError.value = null
  submitting.value = true

  try {
    const rejection = await submit({ url: form.url.trim(), commit: form.commit.trim() })
    if (rejection) {
      formError.value = rejection
      return
    }
    form.commit = ''
  }
  finally {
    submitting.value = false
  }
}

const STATUS_TONE = {
  queued: 'text-muted-foreground',
  cloning: 'text-muted-foreground animate-pulse',
  running: 'text-muted-foreground animate-spin',
  done: 'text-status-good',
  failed: 'text-status-critical',
} as const

const STATUS_ICON = {
  queued: ClockIcon,
  cloning: GitBranchIcon,
  running: LoaderIcon,
  done: CircleCheckIcon,
  failed: CircleAlertIcon,
} as const
</script>

<template>
  <section class="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
    <div class="flex flex-col gap-1">
      <h2 class="text-lg font-semibold">
        漏洞审查
      </h2>
      <p class="text-muted-foreground text-sm">
        填入仓库地址和 commit，服务会把它拉取到专用审计目录，再交给 agent 执行审查。
      </p>
    </div>

    <Card>
      <CardHeader>
        <CardTitle>新建审查</CardTitle>
        <CardDescription>一次只跑一个任务，提交后会排队；进度和结论在下方列表里更新。</CardDescription>
      </CardHeader>
      <CardContent>
        <form @submit.prevent="onSubmit">
          <FieldGroup>
            <Field :data-invalid="Boolean(formError)">
              <FieldLabel for="audit-url">
                仓库地址
              </FieldLabel>
              <Input
                id="audit-url"
                v-model="form.url"
                placeholder="https://github.com/owner/repo.git"
                autocomplete="off"
                :aria-invalid="Boolean(formError)"
              />
              <FieldDescription>支持 http(s)://、git://、ssh:// 或 git@ 形式的远程地址。</FieldDescription>
            </Field>

            <Field :data-invalid="Boolean(formError)">
              <FieldLabel for="audit-commit">
                Commit
              </FieldLabel>
              <Input
                id="audit-commit"
                v-model="form.commit"
                placeholder="分支名、标签或提交哈希"
                autocomplete="off"
                :aria-invalid="Boolean(formError)"
              />
              <FieldDescription>会以 detached HEAD 检出这个 commit。</FieldDescription>
            </Field>

            <FieldError v-if="formError">
              {{ formError }}
            </FieldError>

            <Button type="submit" class="w-fit" :disabled="!canSubmit">
              <Spinner v-if="submitting" data-icon="inline-start" />
              <PlayIcon v-else data-icon="inline-start" />
              开始审查
            </Button>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>

    <Card>
      <CardHeader>
        <CardTitle>审查任务</CardTitle>
        <CardDescription>{{ tasks.length }} 个任务，按时间倒序。</CardDescription>
      </CardHeader>

      <CardContent class="p-2">
        <div v-if="loading" class="flex flex-col gap-1 p-1">
          <Skeleton v-for="n in 3" :key="n" class="h-14 rounded-md" />
        </div>

        <Empty v-else-if="tasks.length === 0" class="min-h-40">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <FileSearchIcon />
            </EmptyMedia>
            <EmptyTitle>{{ NO_DATA }}</EmptyTitle>
            <EmptyDescription>还没有审查任务，在上面填写仓库地址和 commit 就能开始。</EmptyDescription>
          </EmptyHeader>
        </Empty>

        <div v-else class="flex flex-col gap-0.5">
          <Item
            v-for="task in tasks"
            :key="task.id"
            as="button"
            type="button"
            size="xs"
            class="hover:bg-muted/60 focus-visible:ring-ring/50 w-full flex-col items-start rounded-md border-0 px-3 py-2 text-left outline-none focus-visible:ring-3"
            @click="openTask(task)"
          >
            <ItemContent class="gap-1">
              <div class="flex w-full items-center gap-2">
                <ItemTitle class="min-w-0 flex-1 truncate font-mono text-xs">
                  {{ task.url }}
                </ItemTitle>
                <Badge variant="outline" class="shrink-0">
                  <component :is="STATUS_ICON[task.status]" :class="STATUS_TONE[task.status]" />
                  {{ AUDIT_STATUS_LABELS[task.status] }}
                </Badge>
              </div>

              <ItemDescription class="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-xs">
                <span>@ {{ task.commit }}</span>
                <span aria-hidden="true">·</span>
                <span>{{ formatRelative(task.createdAt) }}</span>
                <template v-if="task.startedAt">
                  <span aria-hidden="true">·</span>
                  <span>用时 {{ elapsedLabel(task.startedAt, task.endedAt) }}</span>
                </template>
              </ItemDescription>

              <ItemDescription v-if="task.error" class="text-status-critical line-clamp-1 text-xs">
                {{ task.error }}
              </ItemDescription>
              <ItemDescription v-else-if="task.verdict" class="line-clamp-1 text-xs">
                {{ orNoData(task.verdict.split('\n')[0]) }}
              </ItemDescription>
              <!-- 进行中的任务还没有结论，状态徽标已经说明了，这行先不占位。 -->
              <ItemDescription v-else-if="task.status === 'done'" class="text-xs">
                {{ NO_DATA }}
              </ItemDescription>
            </ItemContent>
          </Item>
        </div>
      </CardContent>
    </Card>

    <AuditTaskSheet v-model:open="sheetOpen" :task="selected" />
  </section>
</template>
