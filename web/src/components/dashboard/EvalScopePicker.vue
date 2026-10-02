<script setup lang="ts">
import type { EvalItem, EvalScope, EvalScopeTypes } from '@/lib/types'
import { CheckIcon, FilterXIcon, PlayIcon, SearchIcon } from '@lucide/vue'
import { computed, onUnmounted, reactive, ref, watch } from 'vue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Field, FieldDescription, FieldError, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { useEvaluation } from '@/composables/useEvaluation'
import { NO_DATA } from '@/lib/format'

const emit = defineEmits<{ started: [runId: string] }>()

const {
  datasets,
  datasetsLoading,
  dataset,
  datasetId,
  items,
  itemsLoading,
  preview,
  previewUnavailable,
  reachable,
  selectDataset,
  loadItems,
  refreshPreview,
  startRun,
} = useEvaluation()

/** No filter option means "all of them", which reka-ui spells as the empty string. */
const ALL = '__all__'

const filters = reactive({ search: '', project: ALL, cwe: ALL })
const types = ref<EvalScopeTypes>('both')

/**
 * Items ticked by hand. Kept separately from the filters because it outlives
 * them: narrowing the list afterwards must not silently drop a row that was
 * already picked. An empty set is what makes a scope mean "everything the
 * filters match".
 */
const selected = ref(new Set<string>())

const typeOptions = computed(() => items.value?.facets.typeOptions ?? [])
const visible = computed<EvalItem[]>(() => items.value?.items ?? [])
const selectedTypeOption = computed(() =>
  typeOptions.value.find(option => option.value === types.value) ?? null,
)

const allVisibleSelected = computed(() =>
  visible.value.length > 0 && visible.value.every(item => selected.value.has(item.id)),
)
const someVisibleSelected = computed(() =>
  visible.value.some(item => selected.value.has(item.id)),
)

/** The filters, as the bridge's scope object. */
const filterScope = computed(() => ({
  projects: filters.project === ALL ? [] : [filters.project],
  cweIds: filters.cwe === ALL ? [] : [filters.cwe],
  search: filters.search.trim(),
}))

/**
 * What will be created. A hand-made selection wins over the filters — that is
 * the same precedence the bridge applies, so what is previewed is what runs.
 */
const scope = computed<EvalScope>(() => ({
  ...(selected.value.size
    ? { itemIds: [...selected.value] }
    : filterScope.value),
  types: types.value,
}))

const submitting = ref(false)
const formError = ref<string | null>(null)
const canStart = computed(() =>
  !submitting.value && Boolean(preview.value && preview.value.sampleCount > 0),
)

/** Toggling the header checkbox selects or clears exactly the rows on screen. */
function toggleAllVisible() {
  const next = new Set(selected.value)
  if (allVisibleSelected.value)
    visible.value.forEach(item => next.delete(item.id))
  else
    visible.value.forEach(item => next.add(item.id))
  selected.value = next
}

function toggleItem(id: string) {
  const next = new Set(selected.value)
  if (next.has(id))
    next.delete(id)
  else
    next.add(id)
  selected.value = next
}

function clearSelection() {
  selected.value = new Set()
}

function clearFilters() {
  filters.search = ''
  filters.project = ALL
  filters.cwe = ALL
}

function setTypes(value: unknown) {
  if (value === 'vul' || value === 'sec' || value === 'both')
    types.value = value
}

/** Only filters reload the rows. A manual selection or sample type change must
 * update the preview without replacing the list with its loading skeleton. */
let itemsTimer: ReturnType<typeof setTimeout> | null = null
watch(
  [
    () => filters.search,
    () => filters.project,
    () => filters.cwe,
  ],
  () => {
    if (itemsTimer)
      clearTimeout(itemsTimer)
    itemsTimer = setTimeout(() => void loadItems(filterScope.value), 300)
  },
)

/** Keep the preview in step with every choice, including row and type picks. */
let previewTimer: ReturnType<typeof setTimeout> | null = null
watch(
  [
    () => filters.search,
    () => filters.project,
    () => filters.cwe,
    types,
    selected,
    datasetId,
  ],
  () => {
    if (previewTimer)
      clearTimeout(previewTimer)
    previewTimer = setTimeout(() => refreshPreview(scope.value), 300)
  },
  { immediate: true },
)

onUnmounted(() => {
  if (itemsTimer)
    clearTimeout(itemsTimer)
  if (previewTimer)
    clearTimeout(previewTimer)
})

async function onStart() {
  formError.value = null
  submitting.value = true
  try {
    const { run, error } = await startRun(scope.value)
    if (error || !run) {
      formError.value = error ?? '评测没有创建成功。'
      return
    }
    emit('started', run.id)
  }
  finally {
    submitting.value = false
  }
}
</script>

<template>
  <Card>
    <CardHeader>
      <CardTitle>测评范围</CardTitle>
      <CardDescription>
        先按条件筛出要测评的项，或者逐个勾选；一项会按下面的类型展开成一个或多个样例。
      </CardDescription>
    </CardHeader>

    <CardContent class="flex flex-col gap-4">
      <Empty v-if="datasetsLoading" class="min-h-32">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <SearchIcon />
          </EmptyMedia>
          <EmptyTitle>正在读取数据集…</EmptyTitle>
        </EmptyHeader>
      </Empty>

      <Empty v-else-if="datasets.length === 0" class="min-h-32">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FilterXIcon />
          </EmptyMedia>
          <EmptyTitle>{{ reachable ? NO_DATA : '无法连接桥接服务' }}</EmptyTitle>
          <EmptyDescription>
            {{ reachable
              ? '桥接服务没有读到任何数据集，确认 benchmark/ 下有数据集文件后刷新页面。'
              : '测评数据全部来自桥接服务，请先启动它再刷新页面。' }}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>

      <template v-else>
        <div v-if="datasets.length > 1" class="flex flex-col gap-1">
          <FieldLabel for="eval-dataset">数据集</FieldLabel>
          <Select :model-value="datasetId" @update:model-value="value => selectDataset(String(value), filterScope)">
            <SelectTrigger id="eval-dataset" class="w-96">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem v-for="entry in datasets" :key="entry.id" :value="entry.id">
                {{ entry.name }}
              </SelectItem>
            </SelectContent>
          </Select>
        </div>

        <p v-if="dataset" class="text-muted-foreground text-sm">
          {{ dataset.description }}
        </p>

        <!--
          Each control's width goes on its `Field`, not on the control itself:
          `Field` carries `*:w-full`, and that selector is specific enough to
          override a width class on the child. Without one every filter takes a
          whole line and the row stacks instead of reading as a row.
        -->
        <div class="flex flex-wrap items-end gap-3">
          <Field class="w-64">
            <FieldLabel for="eval-search">搜索</FieldLabel>
            <Input id="eval-search" v-model="filters.search" placeholder="项目 / CVE / CWE / 文件路径" autocomplete="off" />
          </Field>

          <Field class="w-56">
            <FieldLabel for="eval-project">项目</FieldLabel>
            <Select v-model="filters.project">
              <SelectTrigger id="eval-project">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem :value="ALL">全部项目</SelectItem>
                <SelectItem
                  v-for="option in items?.facets.projects ?? []"
                  :key="option.value"
                  :value="option.value"
                >
                  {{ option.value }}（{{ option.count }}）
                </SelectItem>
              </SelectContent>
            </Select>
          </Field>

          <Field class="w-40">
            <FieldLabel for="eval-cwe">CWE</FieldLabel>
            <Select v-model="filters.cwe">
              <SelectTrigger id="eval-cwe">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem :value="ALL">全部 CWE</SelectItem>
                <SelectItem
                  v-for="option in items?.facets.cweIds ?? []"
                  :key="option.value"
                  :value="option.value"
                >
                  {{ option.value }}（{{ option.count }}）
                </SelectItem>
              </SelectContent>
            </Select>
          </Field>

          <Button variant="ghost" type="button" @click="clearFilters">
            <FilterXIcon data-icon="inline-start" />
            清空筛选
          </Button>
        </div>

        <div class="rounded-lg border">
          <div class="flex flex-wrap items-center gap-2 border-b px-3 py-2">
            <Checkbox
              :model-value="allVisibleSelected ? true : (someVisibleSelected ? 'indeterminate' : false)"
              aria-label="全选当前筛选出的项"
              @update:model-value="toggleAllVisible"
            />
            <span class="text-sm">共 {{ visible.length }} 项</span>
            <span class="text-muted-foreground text-xs">
              <template v-if="selected.size">已选 {{ selected.size }} 项</template>
              <template v-else>未勾选则测评上面筛选出的全部</template>
            </span>
            <Button v-if="selected.size" variant="ghost" size="sm" class="ml-auto" type="button" @click="clearSelection">
              清空选择
            </Button>
          </div>

          <div v-if="itemsLoading" class="flex flex-col gap-1 p-2">
            <Skeleton v-for="n in 4" :key="n" class="h-10 rounded-md" />
          </div>

          <Empty v-else-if="visible.length === 0" class="min-h-28">
            <EmptyHeader>
              <EmptyTitle>这个筛选条件没有匹配的项</EmptyTitle>
              <EmptyDescription>清空筛选就能看到数据集里的全部项。</EmptyDescription>
            </EmptyHeader>
          </Empty>

          <ScrollArea v-else class="h-72">
            <button
              v-for="item in visible"
              :key="item.id"
              type="button"
              :aria-pressed="selected.has(item.id)"
              class="hover:bg-muted/60 focus-visible:ring-ring/50 flex w-full items-start gap-2.5 px-3 py-2 text-left outline-none focus-visible:ring-3"
              @click="toggleItem(item.id)"
            >
              <span
                class="border-input mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-[4px] border transition-colors"
                :class="selected.has(item.id) ? 'border-primary bg-primary text-primary-foreground' : ''"
              >
                <CheckIcon v-if="selected.has(item.id)" class="size-3.5" />
              </span>
              <span class="min-w-0 flex-1">
                <span class="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span class="font-mono text-xs">{{ item.id }}</span>
                  <span class="text-sm font-medium">{{ item.projectName }}</span>
                  <Badge v-for="cwe in item.cweIds" :key="cwe" variant="outline">{{ cwe }}</Badge>
                  <Badge v-for="cve in item.cveIds" :key="cve" variant="secondary">{{ cve }}</Badge>
                </span>
                <span class="text-muted-foreground block truncate font-mono text-xs">{{ item.filePath }}</span>
              </span>
            </button>
          </ScrollArea>
        </div>

        <Field>
          <FieldLabel>样例类型</FieldLabel>
          <ToggleGroup
            :model-value="types"
            type="single"
            variant="outline"
            size="sm"
            @update:model-value="setTypes"
          >
            <ToggleGroupItem v-for="option in typeOptions" :key="option.value" :value="option.value">
              {{ option.label }}
            </ToggleGroupItem>
          </ToggleGroup>
          <FieldDescription>
            {{ selectedTypeOption?.detail ?? NO_DATA }}
          </FieldDescription>
        </Field>

        <FieldError v-if="formError">
          {{ formError }}
        </FieldError>

        <div class="flex flex-wrap items-center gap-3">
          <Button type="button" :disabled="!canStart" @click="onStart">
            <Spinner v-if="submitting" data-icon="inline-start" />
            <PlayIcon v-else data-icon="inline-start" />
            开始测评
          </Button>
          <span v-if="preview" class="text-sm">{{ preview.title }}</span>
          <span v-else-if="previewUnavailable" class="text-status-critical text-sm">
            无法连接桥接服务，范围暂时解析不了
          </span>
          <span v-else class="text-muted-foreground text-sm">正在解析范围…</span>
        </div>
      </template>
    </CardContent>
  </Card>
</template>
