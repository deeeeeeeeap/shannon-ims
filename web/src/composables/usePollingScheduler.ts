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

  // window.clearTimeout, to match the window.setTimeout in schedule(). These are
  // the same function in a browser, so the previous bare clearTimeout() worked in
  // production -- but the asymmetry means the timer cannot be cancelled under any
  // host that provides the pair on `window` only, which silently leaks the poll.
  function clearTimer() {
    if (timer.value != null) {
      window.clearTimeout(timer.value)
      timer.value = null
    }
  }

  function nextDelay() {
    if (typeof document !== 'undefined' && document.hidden) {
      return Math.max(currentInterval.value, bgInterval)
    }
    return currentInterval.value
  }

  // When the pending timer was armed, in epoch ms, so a visibility change can work
  // out how much of it has already elapsed.
  let scheduledAt = 0
  let scheduledDelay = 0

  function schedule(delay = nextDelay()) {
    clearTimer()
    if (stopped.value) return
    scheduledAt = Date.now()
    scheduledDelay = delay
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

  // The visibility listener is bound by start() and released by stop(), not by
  // onMounted/onUnmounted. Tying it to the mount hooks meant a scheduler driven
  // through start() directly -- which is how it is exercised in tests -- polled
  // without ever hearing about the tab becoming visible again, so the re-arm below
  // silently did nothing there.
  let visibilityBound = false

  function bindVisibility() {
    if (visibilityBound || typeof document === 'undefined') return
    document.addEventListener('visibilitychange', onVisibilityChange, { passive: true })
    visibilityBound = true
  }

  function unbindVisibility() {
    if (!visibilityBound || typeof document === 'undefined') return
    document.removeEventListener('visibilitychange', onVisibilityChange)
    visibilityBound = false
  }

  function start() {
    stopped.value = false
    currentInterval.value = intervalMs
    bindVisibility()
    schedule(options.immediate ? 0 : intervalMs)
  }

  function stop() {
    stopped.value = true
    clearTimer()
    unbindVisibility()
  }

  function trigger() {
    schedule(0)
  }

  // Re-arm the pending timer when the tab becomes visible again.
  //
  // The delay is chosen once, at schedule() time, from whether the document was
  // hidden then. So a tab backgrounded with a 120s background interval kept that
  // 120s even after the operator came back -- on the device pages that meant up to
  // two minutes of stale state while looking straight at it.
  //
  // This deliberately does NOT fire the task immediately: an instant refetch on
  // every tab focus is the "yanked back" feel the previous version was avoiding.
  // Instead the remaining wait is recomputed against the foreground interval and
  // credited with the time already served, so a long background delay collapses to
  // whatever is left of the short one -- usually firing within a few seconds, and
  // immediately only if the foreground interval had already fully elapsed.
  function onVisibilityChange() {
    if (typeof document === 'undefined' || document.hidden) return
    if (stopped.value || running.value || timer.value == null) return

    const elapsed = Date.now() - scheduledAt
    const foregroundDelay = currentInterval.value
    if (scheduledDelay <= foregroundDelay) return

    schedule(Math.max(0, foregroundDelay - elapsed))
  }

  onMounted(start)
  onUnmounted(stop)

  if (options.enabled) {
    watch(() => options.enabled!.value, (v) => { if (v) trigger() })
  }

  return { running, currentInterval, start, stop, trigger }
}
