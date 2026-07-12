import { onMounted, onUnmounted, ref, watch } from 'vue'
import type { Ref } from 'vue'

export type PollSchedulerOptions = {
  enabled?: Ref<boolean>
  immediate?: boolean
  backgroundIntervalMs?: number
  backoffFactor?: number
  maxIntervalMs?: number
}

export function usePollingScheduler(task: () => Promise<void> | void, intervalMs: number, options: PollSchedulerOptions = {}) {
  const running = ref(false)
  const stopped = ref(false)
  const timer = ref<number | null>(null)
  const currentInterval = ref(intervalMs)

  const backoffFactor = options.backoffFactor ?? 2
  const maxIntervalMs = options.maxIntervalMs ?? 60000
  const bgInterval = options.backgroundIntervalMs ?? Math.max(intervalMs, 60000)

  function clearTimer() {
    if (timer.value != null) {
      clearTimeout(timer.value)
      timer.value = null
    }
  }

  function nextDelay() {
    if (typeof document !== 'undefined' && document.hidden) {
      return Math.max(currentInterval.value, bgInterval)
    }
    return currentInterval.value
  }

  function schedule(delay = nextDelay()) {
    clearTimer()
    if (stopped.value) return
    timer.value = window.setTimeout(() => void tick(), delay)
  }

  async function tick() {
    if (stopped.value || running.value) {
      schedule()
      return
    }
    if (options.enabled && !options.enabled.value) {
      schedule()
      return
    }

    running.value = true
    try {
      await task()
      currentInterval.value = intervalMs
    } catch {
      currentInterval.value = Math.min(maxIntervalMs, Math.max(intervalMs, Math.floor(currentInterval.value * backoffFactor)))
    } finally {
      running.value = false
      schedule()
    }
  }

  function start() {
    stopped.value = false
    currentInterval.value = intervalMs
    schedule(options.immediate ? 0 : intervalMs)
  }

  function stop() {
    stopped.value = true
    clearTimer()
  }

  function trigger() {
    schedule(0)
  }

  function onVisibilityChange() {
    // 可见性切换时不再立即抢占刷新，避免页面切后台/前台时产生“被拉回”的体感。
    // 轮询会在下一次调度周期自然执行。
  }

  onMounted(() => {
    start()
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibilityChange, { passive: true })
  })

  onUnmounted(() => {
    stop()
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisibilityChange)
  })

  if (options.enabled) {
    watch(() => options.enabled!.value, (v) => { if (v) trigger() })
  }

  return { running, currentInterval, start, stop, trigger }
}
