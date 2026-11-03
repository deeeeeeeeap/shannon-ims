import test from 'node:test'
import assert from 'node:assert/strict'
import { effectScope, ref, nextTick } from 'vue'

// usePollingScheduler backs all seven polls in the app and had no test coverage.
// The behaviours pinned here are the ones whose failure is invisible: a poll that
// silently stops, or one that keeps a 2-minute background delay after the operator
// has come back to the tab and is staring at stale device state.

type TimerFn = () => void

class FakeClock {
  now = 1_000_000
  private seq = 1
  private timers = new Map<number, { at: number; fn: TimerFn }>()

  setTimeout = (fn: TimerFn, delay: number) => {
    const id = this.seq++
    this.timers.set(id, { at: this.now + delay, fn })
    return id
  }

  clearTimeout = (id: number) => {
    this.timers.delete(id)
  }

  /** Pending delay of the single armed timer, or null. */
  pendingDelay(): number | null {
    const entries = [...this.timers.values()]
    if (entries.length === 0) return null
    return entries[0].at - this.now
  }

  timerCount() {
    return this.timers.size
  }

  /** Advance time and run whatever comes due, innermost first. */
  async advance(ms: number) {
    const target = this.now + ms
    // Guard against a scheduler that re-arms at 0 forever.
    for (let guard = 0; guard < 1000; guard++) {
      const due = [...this.timers.entries()]
        .filter(([, t]) => t.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0]
      if (!due) break
      const [id, timer] = due
      this.timers.delete(id)
      this.now = timer.at
      timer.fn()
      await nextTick()
      await Promise.resolve()
    }
    this.now = target
  }
}

// The globals are installed ONCE and then delegate to whichever clock is current.
// The module under test captures window.setTimeout at import time, so swapping the
// window object per test would leave it holding a dead clock -- which is what made
// the first draft of these tests fail for reasons that had nothing to do with the
// scheduler.
let clock = new FakeClock()
let hidden = false
const listeners = new Map<string, Set<() => void>>()

Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: {
    setTimeout: (fn: TimerFn, delay: number) => clock.setTimeout(fn, delay),
    clearTimeout: (id: number) => clock.clearTimeout(id),
  },
})

Object.defineProperty(globalThis, 'document', {
  configurable: true,
  value: {
    get hidden() { return hidden },
    addEventListener(type: string, fn: () => void) {
      if (!listeners.has(type)) listeners.set(type, new Set())
      listeners.get(type)!.add(fn)
    },
    removeEventListener(type: string, fn: () => void) {
      listeners.get(type)?.delete(fn)
    },
  },
})

// Date.now must follow the fake clock too: the visibility fix measures elapsed time
// with it, and a real Date.now against a fake timer would read ~0ms elapsed.
const realNow = Date.now
Date.now = () => clock.now
void realNow

function installEnv() {
  clock = new FakeClock()
  hidden = false
  listeners.clear()
}

function fireVisibility() {
  for (const fn of listeners.get('visibilitychange') ?? []) fn()
}

const { usePollingScheduler } = await import('../src/composables/usePollingScheduler')

/** Mounts the composable, since it schedules from onMounted. */
function mount(task: () => Promise<void> | void, interval: number, opts: Record<string, unknown> = {}) {
  const scope = effectScope()
  let api: ReturnType<typeof usePollingScheduler> | undefined
  scope.run(() => {
    api = usePollingScheduler(task, interval, opts)
  })
  // effectScope does not run onMounted; call start() to reach the same state.
  api!.start()
  return { scope, api: api! }
}

test('a returning tab does not keep waiting out the background interval', async () => {
  // The regression: the delay was picked at schedule() time from document.hidden,
  // so a tab backgrounded with backgroundIntervalMs 120000 kept 120s even after the
  // operator switched back.
  installEnv()
  let runs = 0
  hidden = true
  const { scope } = mount(() => { runs++ }, 5000, { backgroundIntervalMs: 120000 })

  assert.equal(clock.pendingDelay(), 5000, 'start() uses the plain interval')
  await clock.advance(5000)
  assert.equal(runs, 1)
  // Re-armed while hidden -> background delay.
  assert.equal(clock.pendingDelay(), 120000, 'hidden tab backs off')

  // 3s later the operator comes back.
  await clock.advance(3000)
  hidden = false
  fireVisibility()

  const pending = clock.pendingDelay()
  assert.ok(pending !== null && pending <= 2000,
    `expected the wait to collapse to the foreground remainder, got ${pending}`)

  // It must not have fired on focus alone.
  assert.equal(runs, 1, 'visibility change must not trigger an immediate refetch')

  await clock.advance(2000)
  assert.equal(runs, 2, 'and then it polls on the foreground schedule')
  scope.stop()
})

test('visibility change is a no-op while already on the foreground interval', async () => {
  installEnv()
  const { scope } = mount(() => {}, 5000, { backgroundIntervalMs: 15000 })
  await clock.advance(5000)
  const before = clock.pendingDelay()
  fireVisibility()
  assert.equal(clock.pendingDelay(), before, 'must not restart a healthy short timer')
  scope.stop()
})

test('a failing task backs off and recovers on success', async () => {
  installEnv()
  let fail = true
  const { scope } = mount(() => { if (fail) throw new Error('boom') }, 1000, {
    backoffFactor: 2, maxIntervalMs: 8000,
  })

  await clock.advance(1000)
  assert.equal(clock.pendingDelay(), 2000, 'first failure doubles')
  await clock.advance(2000)
  assert.equal(clock.pendingDelay(), 4000, 'second failure doubles again')

  fail = false
  await clock.advance(4000)
  assert.equal(clock.pendingDelay(), 1000, 'success resets to the base interval')
  scope.stop()
})

test('backoff is capped', async () => {
  installEnv()
  const { scope } = mount(() => { throw new Error('always') }, 1000, {
    backoffFactor: 10, maxIntervalMs: 5000,
  })
  for (let i = 0; i < 6; i++) {
    await clock.advance(clock.pendingDelay() ?? 0)
  }
  assert.equal(clock.pendingDelay(), 5000, 'must not exceed maxIntervalMs')
  scope.stop()
})

test('a slow task is never run concurrently with itself', async () => {
  installEnv()
  let active = 0
  let maxActive = 0
  let release: (() => void) | null = null

  const { scope } = mount(async () => {
    active++
    maxActive = Math.max(maxActive, active)
    await new Promise<void>(r => { release = r })
    active--
  }, 1000)

  await clock.advance(1000)
  // Task is in flight; drive several more ticks past it.
  await clock.advance(5000)
  assert.equal(maxActive, 1, 'overlapping polls would corrupt shared state')

  release?.()
  await nextTick()
  scope.stop()
})

test('stop() cancels the pending timer and start() resumes', async () => {
  installEnv()
  let runs = 0
  const { scope, api } = mount(() => { runs++ }, 1000)

  api.stop()
  assert.equal(clock.timerCount(), 0, 'stop must leave no armed timer')
  await clock.advance(10000)
  assert.equal(runs, 0, 'a stopped scheduler must not poll')

  api.start()
  await clock.advance(1000)
  assert.equal(runs, 1, 'start must resume polling')
  scope.stop()
})

test('an enabled=false gate skips the task but keeps the loop alive', async () => {
  installEnv()
  let runs = 0
  const enabled = ref(false)
  const { scope } = mount(() => { runs++ }, 1000, { enabled })

  await clock.advance(3000)
  assert.equal(runs, 0, 'gated off -> no work')
  assert.ok(clock.timerCount() > 0, 'but the loop must stay armed')

  enabled.value = true
  await nextTick()
  await clock.advance(1000)
  assert.ok(runs >= 1, 're-enabling resumes work')
  scope.stop()
})
