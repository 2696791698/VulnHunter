<script setup lang="ts">
import type { AuditMode, AuditSubmission, AuditTask } from '@/lib/types'
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
import { Textarea } from '@/components/ui/textarea'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { useAuditTasks } from '@/composables/useAuditTasks'
import {
  AUDIT_MODE_LABELS,
  AUDIT_STATUS_LABELS,
  NO_DATA,
  elapsedLabel,
  formatRelative,
  orNoData,
} from '@/lib/format'

const { tasks, loading, submit } = useAuditTasks()

const form = reactive({
  mode: 'project' as AuditMode,
  url: '',
  commit: '',
  filePath: '',
  functionCode: '',
})
const submitting = ref(false)
const formError = ref<string | null>(null)

/** The group is `type="single"`, but switching away is not a state to allow. */
function setMode(value: unknown) {
  if (value === 'project' || value === 'function')
    form.mode = value
}

// Only what the bridge cannot accept is checked here; the rules themselves (the
// url and ref whitelists, the path shape, the code length) stay in the bridge,
// whose message is what the form reports.
const canSubmit = computed(() => {
  if (submitting.value || !form.url.trim() || !form.commit.trim())
    return false
  if (form.mode === 'function')
    return form.filePath.trim().length > 0 && form.functionCode.trim().length > 0
  return true
})

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

  const url = form.url.trim()
  const commit = form.commit.trim()
  const payload: AuditSubmission = form.mode === 'function'
    ? { url, commit, mode: 'function', filePath: form.filePath.trim(), functionCode: form.functionCode }
    : { url, commit, mode: 'project' }

  try {
    const rejection = await submit(payload)
    if (rejection) {
      formError.value = rejection
      return
    }
    form.commit = ''
    form.filePath = ''
    form.functionCode = ''
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
            <Field>
              <FieldLabel>检测模式</FieldLabel>
              <ToggleGroup
                :model-value="form.mode"
                type="single"
                variant="outline"
                size="sm"
                :disabled="submitting"
                @update:model-value="setMode"
              >
                <ToggleGroupItem value="project">
                  项目检测
                </ToggleGroupItem>
                <ToggleGroupItem value="function">
                  函数检测
                </ToggleGroupItem>
              </ToggleGroup>
              <FieldDescription>项目检测审查整个仓库；函数检测只审查你指出的那一个函数。</FieldDescription>
            </Field>

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

            <template v-if="form.mode === 'function'">
              <Field :data-invalid="Boolean(formError)">
                <FieldLabel for="audit-file-path">
                  函数所在文件
                </FieldLabel>
                <Input
                  id="audit-file-path"
                  v-model="form.filePath"
                  placeholder="src/package/module.py"
                  autocomplete="off"
                  class="font-mono"
                  :aria-invalid="Boolean(formError)"
                />
                <FieldDescription>相对项目根目录的路径；检出后会在检出目录里找到它，找不到就直接报错。</FieldDescription>
              </Field>

              <Field :data-invalid="Boolean(formError)">
                <FieldLabel for="audit-function-code">
                  函数代码
                </FieldLabel>
                <Textarea
                  id="audit-function-code"
                  v-model="form.functionCode"
                  placeholder="def handler(request):&#10;    ..."
                  spellcheck="false"
                  class="max-h-80 min-h-32 font-mono text-xs"
                  :aria-invalid="Boolean(formError)"
                />
                <FieldDescription>把函数整段贴进来（含定义那一行），审查只针对这段代码。</FieldDescription>
              </Field>
            </template>

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
                <Badge variant="secondary" class="shrink-0">
                  {{ AUDIT_MODE_LABELS[task.mode] }}
                </Badge>
                <Badge variant="outline" class="shrink-0">
                  <component :is="STATUS_ICON[task.status]" :class="STATUS_TONE[task.status]" />
                  {{ AUDIT_STATUS_LABELS[task.status] }}
                </Badge>
              </div>

              <ItemDescription class="flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-xs">
                <span>@ {{ task.commit }}</span>
                <template v-if="task.filePath">
                  <span aria-hidden="true">·</span>
                  <span class="min-w-0 max-w-64 truncate">{{ task.filePath }}</span>
                </template>
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
