<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { toast } from 'vue-sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  CheckIcon,
  ChevronRightIcon,
  CloudIcon,
  EyeIcon,
  EyeOffIcon,
  KeyRoundIcon,
  MinusIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  SparklesIcon,
} from '@lucide/vue'
import {
  fetchConcurrencyConfiguration,
  fetchModelConfiguration,
  saveConcurrencyConfiguration,
  saveModelConfiguration,
} from '@/lib/api'
import type { ModelConfiguration } from '@/lib/types'

const PROVIDERS = [
  {
    id: 'openai',
    name: 'OpenAI',
    note: '官方 API',
    baseUrl: 'https://api.openai.com/v1',
    mark: 'O',
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    note: '推理与通用',
    baseUrl: 'https://api.deepseek.com',
    mark: 'D',
  },
  {
    id: 'qwen',
    name: '通义千问',
    note: 'DashScope 兼容接口',
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    mark: 'Q',
  },
  {
    id: 'openrouter',
    name: 'OpenRouter',
    note: '多模型路由',
    baseUrl: 'https://openrouter.ai/api/v1',
    mark: 'R',
  },
  {
    id: 'siliconflow',
    name: '硅基流动',
    note: 'SiliconFlow API',
    baseUrl: 'https://api.siliconflow.cn/v1',
    mark: 'S',
  },
  {
    id: 'custom',
    name: '自定义接口',
    note: 'OpenAI 兼容格式',
    baseUrl: '',
    mark: '↗',
  },
] as const

const REASONING_PRESETS = ['none', 'low', 'medium', 'high', 'xhigh', 'max'] as const
const REASONING_EFFORT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/

const selectedProvider = ref<string>('custom')
const modelName = ref('')
const reasoningPreset = ref('none')
const customReasoningEffort = ref('')
const baseUrl = ref('')
const apiKey = ref('')
const showApiKey = ref(false)
const apiKeyConfigured = ref(false)
const clearApiKey = ref(false)
const loading = ref(true)
const loaded = ref(false)
const saving = ref(false)
const loadError = ref('')
const maxConcurrency = ref(2)
const concurrencyLoaded = ref(false)
const concurrencyLoading = ref(true)
const savingConcurrency = ref(false)
const concurrencyError = ref('')

const provider = computed(() => PROVIDERS.find(item => item.id === selectedProvider.value) ?? PROVIDERS[5])
const isMimoReasoningModel = computed(() => /^mimo-v2\.(5|6)(-|$)/i.test(modelName.value.trim()))
const reasoningEffort = computed(() => reasoningPreset.value === 'custom'
  ? customReasoningEffort.value.trim()
  : reasoningPreset.value)
const hasApiKey = computed(() => apiKeyConfigured.value || Boolean(apiKey.value.trim()))
const canSave = computed(() => loaded.value
  && modelName.value.trim().length > 0
  && REASONING_EFFORT_PATTERN.test(reasoningEffort.value)
  && (hasApiKey.value || clearApiKey.value)
  && !saving.value)
const configurationReady = computed(() => Boolean(modelName.value.trim()) && apiKeyConfigured.value)

function applyConfiguration(configuration: ModelConfiguration) {
  selectedProvider.value = PROVIDERS.some(item => item.id === configuration.provider)
    ? configuration.provider
    : 'custom'
  modelName.value = configuration.modelName
  const savedEffort = configuration.reasoningEffort || 'none'
  reasoningPreset.value = REASONING_PRESETS.some(item => item === savedEffort) ? savedEffort : 'custom'
  customReasoningEffort.value = reasoningPreset.value === 'custom' ? savedEffort : ''
  baseUrl.value = configuration.baseUrl
  apiKeyConfigured.value = configuration.apiKeyConfigured
  apiKey.value = ''
  clearApiKey.value = false
}

async function loadConfiguration() {
  loading.value = true
  loadError.value = ''
  try {
    applyConfiguration(await fetchModelConfiguration())
    loaded.value = true
  }
  catch (error) {
    loadError.value = error instanceof Error ? error.message : '无法读取配置'
  }
  finally {
    loading.value = false
  }
}

async function loadConcurrencyConfiguration() {
  concurrencyLoading.value = true
  concurrencyLoaded.value = false
  concurrencyError.value = ''
  try {
    const configuration = await fetchConcurrencyConfiguration()
    maxConcurrency.value = configuration.maxConcurrency
    concurrencyLoaded.value = true
  }
  catch (error) {
    concurrencyError.value = error instanceof Error ? error.message : '无法读取最大并行数量'
  }
  finally {
    concurrencyLoading.value = false
  }
}

async function adjustConcurrency(amount: number) {
  if (!concurrencyLoaded.value || savingConcurrency.value)
    return

  const next = maxConcurrency.value + amount
  if (next < 1 || next > 16)
    return

  savingConcurrency.value = true
  concurrencyError.value = ''
  try {
    const saved = await saveConcurrencyConfiguration(next)
    maxConcurrency.value = saved.maxConcurrency
    toast.success('最大并行数量已更新', { description: `审查与测评任务上限：${saved.maxConcurrency}` })
  }
  catch (error) {
    concurrencyError.value = error instanceof Error ? error.message : '保存最大并行数量失败'
    toast.error('保存失败', { description: concurrencyError.value })
  }
  finally {
    savingConcurrency.value = false
  }
}

function chooseProvider(id: string) {
  const next = PROVIDERS.find(item => item.id === id)
  if (!next)
    return
  selectedProvider.value = next.id
  baseUrl.value = next.baseUrl
  modelName.value = ''
}

async function saveConfiguration() {
  if (!canSave.value)
    return

  saving.value = true
  try {
    const saved = await saveModelConfiguration({
      provider: selectedProvider.value,
      modelName: modelName.value.trim(),
      reasoningEffort: reasoningEffort.value,
      baseUrl: baseUrl.value.trim(),
      ...(apiKey.value.trim() && !clearApiKey.value ? { apiKey: apiKey.value.trim() } : {}),
      ...(clearApiKey.value ? { clearApiKey: true } : {}),
    })
    applyConfiguration(saved)
    toast.success('模型设置已保存', { description: '新建的审查与测评任务将使用此模型。' })
  }
  catch (error) {
    toast.error('保存失败', { description: error instanceof Error ? error.message : '请检查桥接服务后重试。' })
  }
  finally {
    saving.value = false
  }
}

const safeEndpoint = computed(() => {
  if (!baseUrl.value.trim())
    return '使用 OpenAI 默认地址'
  try {
    const url = new URL(baseUrl.value)
    return `${url.host}${url.pathname.replace(/\/$/, '')}`
  }
  catch {
    return baseUrl.value
  }
})

onMounted(() => {
  void loadConfiguration()
  void loadConcurrencyConfiguration()
})
</script>

<template>
  <section class="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 pb-8 md:px-6 lg:px-8">
    <div class="flex flex-wrap items-end justify-between gap-4 border-b pb-5">
      <div class="flex items-start gap-4">
        <div class="bg-primary text-primary-foreground flex size-11 shrink-0 items-center justify-center rounded-xl">
          <SparklesIcon class="size-5" />
        </div>
        <div class="flex flex-col gap-1">
          <p class="text-muted-foreground text-[11px] font-semibold tracking-[0.18em] uppercase">
            Runtime / Configuration
          </p>
          <h1 class="text-2xl font-semibold tracking-tight">
            配置
          </h1>
          <p class="text-muted-foreground max-w-2xl text-sm">
            配置漏洞审查与数据集测评使用的语言模型，以及任务的最大并行数量。
          </p>
        </div>
      </div>
      <Badge v-if="configurationReady" variant="secondary" class="gap-1.5 rounded-full px-3 py-1">
        <span class="bg-status-good size-1.5 rounded-full" aria-hidden="true" />
        已配置
      </Badge>
      <Badge v-else variant="outline" class="rounded-full px-3 py-1">
        尚未配置
      </Badge>
    </div>

    <div v-if="loadError" class="border-status-warning/40 bg-status-warning/5 flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3">
      <div class="flex items-start gap-3">
        <CloudIcon class="text-status-warning mt-0.5 size-4 shrink-0" />
        <div>
          <p class="text-sm font-medium">暂时无法连接配置服务</p>
          <p class="text-muted-foreground text-xs">{{ loadError }}。请启动桥接服务后重新读取。</p>
        </div>
      </div>
      <Button variant="outline" size="sm" :disabled="loading" @click="loadConfiguration">
        <RefreshCwIcon data-icon="inline-start" :class="loading ? 'animate-spin' : ''" />
        重新读取
      </Button>
    </div>

    <Card class="gap-0">
      <CardHeader class="flex flex-row flex-wrap items-center justify-between gap-3 pb-4">
        <div>
          <CardTitle class="text-base">最大并行数量</CardTitle>
          <CardDescription class="mt-1">审查与测评共用任务池，Joern 服务上限同步调整。</CardDescription>
        </div>
        <Badge variant="outline" class="rounded-full">范围 1–16</Badge>
      </CardHeader>
      <CardContent class="flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-3">
          <Button
            variant="outline"
            size="icon-lg"
            aria-label="减少最大并行数量"
            :disabled="!concurrencyLoaded || savingConcurrency || maxConcurrency <= 1"
            @click="adjustConcurrency(-1)"
          >
            <MinusIcon />
          </Button>
          <div class="min-w-28 text-center" aria-live="polite">
            <p class="text-2xl font-semibold tabular-nums">{{ concurrencyLoaded ? maxConcurrency : '—' }}</p>
            <p class="text-muted-foreground text-xs">个任务同时运行</p>
          </div>
          <Button
            variant="outline"
            size="icon-lg"
            aria-label="增加最大并行数量"
            :disabled="!concurrencyLoaded || savingConcurrency || maxConcurrency >= 16"
            @click="adjustConcurrency(1)"
          >
            <PlusIcon />
          </Button>
          <span v-if="savingConcurrency" class="text-muted-foreground text-xs">正在保存…</span>
        </div>
        <div class="max-w-xl">
          <p class="text-muted-foreground text-xs leading-relaxed">
            数值会保存到工作区配置，并同步到 CodeBadger。已运行的任务继续执行，新的任务按此上限调度。
          </p>
          <div v-if="concurrencyError" class="mt-2 flex flex-wrap items-center gap-2 text-xs">
            <span class="text-destructive">{{ concurrencyError }}</span>
            <Button variant="ghost" size="sm" :disabled="concurrencyLoading" @click="loadConcurrencyConfiguration">
              <RefreshCwIcon data-icon="inline-start" :class="concurrencyLoading ? 'animate-spin' : ''" />
              重新读取
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>

    <div class="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_19rem]">
      <div class="flex min-w-0 flex-col gap-5">
        <Card class="gap-0 overflow-hidden">
          <CardHeader class="border-b pb-4">
            <div class="flex items-center gap-2">
              <span class="bg-primary/10 text-primary flex size-7 items-center justify-center rounded-lg text-xs font-bold">01</span>
              <div>
                <CardTitle class="text-base">选择服务商</CardTitle>
                <CardDescription class="mt-1">选择预设接口，或填写自定义 OpenAI 兼容服务。</CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent class="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
            <button
              v-for="item in PROVIDERS"
              :key="item.id"
              type="button"
              :aria-pressed="selectedProvider === item.id"
              class="group flex min-h-[76px] items-center gap-3 rounded-xl border p-3 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none"
              :class="selectedProvider === item.id
                ? 'border-primary bg-primary/5 shadow-sm'
                : 'border-border hover:border-foreground/20 hover:bg-muted/40'"
              :disabled="!loaded"
              @click="chooseProvider(item.id)"
            >
              <span
                class="flex size-10 shrink-0 items-center justify-center rounded-xl text-sm font-semibold transition-colors"
                :class="selectedProvider === item.id ? 'bg-primary text-primary-foreground' : 'bg-muted text-foreground'"
              >
                {{ item.mark }}
              </span>
              <span class="flex min-w-0 flex-1 flex-col gap-1">
                <span class="truncate text-sm font-medium">{{ item.name }}</span>
                <span class="text-muted-foreground truncate text-xs">{{ item.note }}</span>
              </span>
              <CheckIcon v-if="selectedProvider === item.id" class="text-primary size-4 shrink-0" />
              <ChevronRightIcon v-else class="text-muted-foreground/60 size-4 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
            </button>
          </CardContent>
        </Card>

        <div class="grid gap-5 lg:grid-cols-2">
          <Card class="gap-0">
            <CardHeader class="pb-4">
              <div class="flex items-center gap-2">
                <span class="bg-primary/10 text-primary flex size-7 items-center justify-center rounded-lg text-xs font-bold">02</span>
                <div>
                  <CardTitle class="text-base">连接参数</CardTitle>
                  <CardDescription class="mt-1">当前选择：{{ provider.name }}</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel for="model-name">模型名称</FieldLabel>
                  <Input
                    id="model-name"
                    v-model="modelName"
                    placeholder="输入服务商提供的模型 ID"
                    autocomplete="off"
                    :disabled="!loaded"
                    required
                  />
                  <FieldDescription>填写服务商提供的模型 ID，审查和测评会共用此模型。</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel for="model-base-url">API 基础地址</FieldLabel>
                  <Input
                    id="model-base-url"
                    v-model="baseUrl"
                    inputmode="url"
                    placeholder="https://api.example.com/v1"
                    autocomplete="url"
                    :disabled="!loaded"
                  />
                  <FieldDescription>预设地址可直接使用；自定义接口需填写完整的 HTTP(S) 地址。</FieldDescription>
                </Field>
                <Field>
                  <FieldLabel for="model-reasoning-effort">推理强度</FieldLabel>
                  <Select :model-value="reasoningPreset" :disabled="!loaded" @update:model-value="value => reasoningPreset = String(value)">
                    <SelectTrigger id="model-reasoning-effort" class="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem v-for="effort in REASONING_PRESETS" :key="effort" :value="effort">
                        {{ effort }}
                      </SelectItem>
                      <SelectItem value="custom">自定义</SelectItem>
                    </SelectContent>
                  </Select>
                  <Input
                    v-if="reasoningPreset === 'custom'"
                    id="model-custom-reasoning-effort"
                    v-model="customReasoningEffort"
                    placeholder="输入服务商支持的档位"
                    autocomplete="off"
                    maxlength="64"
                    :disabled="!loaded"
                    :aria-invalid="customReasoningEffort.length > 0 && !REASONING_EFFORT_PATTERN.test(customReasoningEffort.trim())"
                  />
                  <FieldDescription v-if="isMimoReasoningModel">
                    MiMo 只支持思考开关：none 关闭，其他档位均开启；low 到 max 不区分强度。
                  </FieldDescription>
                  <FieldDescription v-else>默认 none；其他档位由模型服务商决定是否支持。自定义值最多 64 个字符。</FieldDescription>
                </Field>
              </FieldGroup>
            </CardContent>
          </Card>

          <Card class="gap-0">
            <CardHeader class="pb-4">
              <div class="flex items-center gap-2">
                <span class="bg-primary/10 text-primary flex size-7 items-center justify-center rounded-lg text-xs font-bold">03</span>
                <div>
                  <CardTitle class="text-base">访问凭据</CardTitle>
                  <CardDescription class="mt-1">密钥保存在桥接服务环境中，不会回传到页面。</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <FieldGroup>
                <Field>
                  <FieldLabel for="model-api-key">API Key</FieldLabel>
                  <div class="relative">
                    <KeyRoundIcon class="text-muted-foreground pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2" />
                    <Input
                      id="model-api-key"
                      v-model="apiKey"
                      :type="showApiKey ? 'text' : 'password'"
                      :placeholder="apiKeyConfigured ? '已保存，留空则保持不变' : '粘贴 API Key'"
                      autocomplete="new-password"
                      class="pr-10 pl-9"
                      :disabled="!loaded || clearApiKey"
                    />
                    <button
                      type="button"
                      class="text-muted-foreground hover:text-foreground absolute top-1/2 right-3 -translate-y-1/2 rounded-sm focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                      :aria-label="showApiKey ? '隐藏 API Key' : '显示 API Key'"
                      :disabled="!loaded || clearApiKey"
                      @click="showApiKey = !showApiKey"
                    >
                      <EyeOffIcon v-if="showApiKey" class="size-4" />
                      <EyeIcon v-else class="size-4" />
                    </button>
                  </div>
                  <FieldDescription>
                    {{ apiKeyConfigured ? '输入新密钥即可替换；留空会保留当前密钥。' : '首次配置需要 API Key。' }}
                  </FieldDescription>
                </Field>
                <label v-if="apiKeyConfigured" class="text-muted-foreground flex cursor-pointer items-center gap-2 text-sm">
                  <Checkbox
                    :checked="clearApiKey"
                    :disabled="!loaded"
                    @update:checked="clearApiKey = $event === true"
                  />
                  清除已保存的密钥
                </label>
              </FieldGroup>
              <div class="bg-muted/50 text-muted-foreground mt-5 flex items-start gap-2 rounded-lg p-3 text-xs leading-relaxed">
                <KeyRoundIcon class="mt-0.5 size-3.5 shrink-0" />
                密钥只通过本地桥接服务写入工作区配置，不会显示在请求读取结果中。
              </div>
            </CardContent>
          </Card>
        </div>

        <Card class="gap-0 border-dashed">
          <CardFooter class="flex flex-wrap items-center justify-between gap-3 p-4">
            <p class="text-muted-foreground max-w-2xl text-xs leading-relaxed">
              保存后立即应用于新建的审查与测评任务。已经运行中的任务会继续使用启动时的配置。
            </p>
            <div class="flex items-center gap-2">
              <Button variant="outline" :disabled="!loaded || loading || saving" @click="loadConfiguration">
                <RefreshCwIcon data-icon="inline-start" />
                还原
              </Button>
              <Button :disabled="!canSave" @click="saveConfiguration">
                <SaveIcon data-icon="inline-start" />
                {{ saving ? '正在保存…' : '保存配置' }}
              </Button>
            </div>
          </CardFooter>
        </Card>
      </div>

      <aside class="flex flex-col gap-5 xl:sticky xl:top-6">
        <Card class="overflow-hidden">
          <div class="bg-primary h-1.5" />
          <CardHeader class="pb-3">
            <div class="flex items-center justify-between gap-3">
              <CardTitle class="text-sm font-semibold">当前使用</CardTitle>
              <Badge :variant="configurationReady ? 'secondary' : 'outline'" class="rounded-full">
                {{ configurationReady ? '就绪' : '待配置' }}
              </Badge>
            </div>
            <CardDescription>新建任务将使用此连接</CardDescription>
          </CardHeader>
          <CardContent class="flex flex-col gap-4 pb-5">
            <div class="bg-muted/60 flex items-center gap-3 rounded-xl p-3">
              <div class="bg-background flex size-10 items-center justify-center rounded-lg border text-sm font-semibold">
                {{ provider.mark }}
              </div>
              <div class="min-w-0">
                <p class="truncate text-sm font-medium">{{ provider.name }}</p>
                <p class="text-muted-foreground truncate text-xs">{{ modelName || '尚未选择模型' }}</p>
              </div>
            </div>
            <div class="flex flex-col gap-2.5 text-xs">
              <div class="flex items-center justify-between gap-3">
                <span class="text-muted-foreground">API 地址</span>
                <span class="max-w-[12rem] truncate text-right font-mono">{{ safeEndpoint }}</span>
              </div>
              <div class="flex items-center justify-between gap-3">
                <span class="text-muted-foreground">推理强度</span>
                <span class="max-w-[12rem] truncate text-right font-mono">{{ reasoningEffort || '待填写' }}</span>
              </div>
              <div class="flex items-center justify-between gap-3">
                <span class="text-muted-foreground">密钥状态</span>
                <span class="inline-flex items-center gap-1.5">
                  <span class="size-1.5 rounded-full" :class="apiKeyConfigured && !clearApiKey ? 'bg-status-good' : 'bg-muted-foreground/40'" />
                  {{ apiKeyConfigured && !clearApiKey ? (apiKey ? '将替换' : '已保存') : (apiKey ? '待保存' : '未配置') }}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card class="bg-muted/30 gap-0">
          <CardHeader class="pb-3">
            <div class="flex items-center gap-2">
              <CloudIcon class="text-primary size-4" />
              <CardTitle class="text-sm">兼容接口</CardTitle>
            </div>
          </CardHeader>
          <CardContent class="text-muted-foreground text-xs leading-relaxed">
            页面使用与后端 Agent 相同的 OpenAI 兼容调用方式。更换服务商时，请确认模型 ID 与 API 地址匹配。
          </CardContent>
        </Card>

        <div v-if="loading" class="flex flex-col gap-2 px-1">
          <Skeleton class="h-3 w-32" />
          <Skeleton class="h-3 w-full" />
        </div>
      </aside>
    </div>
  </section>
</template>
