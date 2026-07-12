import { onMounted, onUnmounted, ref, watch } from 'vue'
import type { Ref } from 'vue'

type SmartPollOptions = {
  enabled?: Ref<boolean>
  immediate?: boolean
  backoff?: {
    factor?: number
    maxIntervalMs?: number
  }
}

export function useSmartPoll(task: () => Promise<void> | void, intervalMs: number, options: SmartPollOptions = {}) {
  const running = ref(false)
  const timer = ref<number | null>(null)
  const stopped = ref(false)
  const currentInterval = ref(intervalMs)

  const factor = options.backoff?.factor ?? 2
  const maxIntervalMs = options.backoff?.maxIntervalMs ?? 60000

  function clearTimer() {
    if (timer.value != null) {
      clearTimeout(timer.value)
      timer.value = null
    }
  }

  async function tick() {
    if (stopped.value) return
    if (running.value) {
      schedule(currentInterval.value)
      return
    }
    if (options.enabled && !options.enabled.value) {
      schedule(currentInterval.value)
      return
    }
    if (typeof document !== 'undefined' && document.hidden) {
      schedule(currentInterval.value)
      return
    }

    running.value = true
    try {
      await task()
      currentInterval.value = intervalMs
    } catch {
      currentInterval.value = Math.min(maxIntervalMs, Math.max(intervalMs, Math.floor(currentInterval.value * factor)))
    } finally {
      running.value = false
      schedule(currentInterval.value)
    }
  }

  function schedule(delayMs: number) {
    clearTimer()
    if (stopped.value) return
    timer.value = window.setTimeout(() => {
      tick()
    }, delayMs)
  }

  function start() {
    stopped.value = false
    currentInterval.value = intervalMs
    schedule(options.immediate ? 0 : currentInterval.value)
  }

  function stop() {
    stopped.value = true
    clearTimer()
  }

  function trigger() {
    schedule(0)
  }

  function onVisibility() {
    if (!document.hidden) {
      trigger()
    }
  }

  onMounted(() => {
    start()
    if (typeof document !== 'undefined') {
      document.addEventListener('visibilitychange', onVisibility, { passive: true })
    }
  })

  onUnmounted(() => {
    stop()
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVisibility)
    }
  })

  if (options.enabled) {
    watch(
      () => options.enabled!.value,
      (v) => {
        if (v) trigger()
      }
    )
  }

  return { running, start, stop, trigger, currentInterval }
}
