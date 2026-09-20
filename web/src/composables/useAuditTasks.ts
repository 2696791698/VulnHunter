import { computed, onMounted, onUnmounted, ref } from 'vue'
import { BridgeError, createAuditTask, fetchAuditTasks } from '@/lib/api'
import type { AuditStatus, AuditSubmission, AuditTask } from '@/lib/types'

const POLL_INTERVAL_MS = 4000

/** Statuses that mean the worker still has something to do. */
const ACTIVE: AuditStatus[] = ['queued', 'cloning', 'running']

const tasks = ref<AuditTask[]>([])
const loading = ref(true)

let timer: ReturnType<typeof setInterval> | null = null

/**
 * Audit tasks come entirely from the bridge — including the queue position and
 * every error, which is the git or agent message verbatim.
 */
export function useAuditTasks() {
  const hasActive = computed(() => tasks.value.some(task => ACTIVE.includes(task.status)))

  async function refresh() {
    try {
      tasks.value = (await fetchAuditTasks()).tasks
    }
    catch {
      tasks.value = []
    }
    finally {
      loading.value = false
    }
  }

  /** Returns null when the task was accepted, or the reason it was not. */
  async function submit(payload: AuditSubmission): Promise<string | null> {
    try {
      const task = await createAuditTask(payload)
      tasks.value = [task, ...tasks.value]
      return null
    }
    catch (error) {
      return error instanceof BridgeError ? error.message : '无法连接桥接服务，请确认它正在运行。'
    }
  }

  onMounted(() => {
    void refresh()

    timer = setInterval(() => {
      if (document.visibilityState === 'visible')
        void refresh()
    }, POLL_INTERVAL_MS)
  })

  onUnmounted(() => {
    if (timer)
      clearInterval(timer)
  })

  return { tasks, loading, hasActive, refresh, submit }
}
