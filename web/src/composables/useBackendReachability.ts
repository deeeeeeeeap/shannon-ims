import { computed, readonly, ref } from 'vue'

// Tracks whether the backend is answering, derived from traffic the app already
// makes rather than from a dedicated health poll.
//
// This exists because the header used to show a permanently ping-ing green dot that
// was wired to nothing: it looked like a health indicator, indicated nothing, and
// animated forever. Reporting real state means the indicator is worth looking at --
// and means the animation budget goes to things that are actually changing.
//
// Every view already polls something on a 5-60s cadence, so success and failure of
// those requests is a truer signal than an extra /ping would be, and costs nothing.

export type BackendState = 'unknown' | 'ok' | 'degraded' | 'down'

// A single failure is usually a transient blip; the UI should not flap on it.
const FAILURES_BEFORE_DEGRADED = 1
const FAILURES_BEFORE_DOWN = 3

const lastOkAt = ref<number | null>(null)
const consecutiveFailures = ref(0)

/** Called from the axios response interceptor on success. */
export function noteBackendSuccess() {
  lastOkAt.value = Date.now()
  consecutiveFailures.value = 0
}

/**
 * Called on failure. Auth rejections are NOT connectivity problems -- the server
 * answered, it just said no -- so they are excluded by the caller.
 */
export function noteBackendFailure() {
  consecutiveFailures.value += 1
}

const state = computed<BackendState>(() => {
  if (lastOkAt.value === null && consecutiveFailures.value === 0) return 'unknown'
  if (consecutiveFailures.value >= FAILURES_BEFORE_DOWN) return 'down'
  if (consecutiveFailures.value > FAILURES_BEFORE_DEGRADED) return 'degraded'
  return 'ok'
})

const label = computed(() => {
  switch (state.value) {
    case 'ok':
      return '已连接'
    case 'degraded':
      return '连接不稳定'
    case 'down':
      return '连接中断'
    case 'unknown':
    default:
      return '连接中'
  }
})

export function useBackendReachability() {
  return {
    state: readonly(state),
    label: readonly(label),
    lastOkAt: readonly(lastOkAt),
  }
}
