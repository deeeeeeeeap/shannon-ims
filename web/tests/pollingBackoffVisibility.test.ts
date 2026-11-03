import test from 'node:test'
import assert from 'node:assert/strict'
import { effectScope, nextTick } from 'vue'

// Self-review probe turned regression test.
//
// The visibility re-arm compares the pending delay against currentInterval, which
// GROWS under failure backoff. So backoff and background throttling interact: once
// currentInterval has backed off past backgroundIntervalMs, the pending delay is no
// longer larger than it, the re-arm decides there is nothing to shorten, and a
// returning operator waits out the full backed-off delay.
//
// That is arguably correct -- a backed-off poll should stay backed off -- but the
// case has to be pinned down either way, because the two mechanisms were designed
// independently and their interaction is not obvious from either one.

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
  clearTimeout = (id: number) => { this.timers.delete(id) }

  pendingDelay(): number | null {
    const e = [...this.timers.values()]
    return e.length ? e[0].at - this.now : null
  }

  async advance(ms: number) {
    const target = this.now + ms
    for (let g = 0; g < 500; g++) {
      const due = [...this.timers.entries()]
        .filter(([, t]) => t.at <= target)
        .sort((a, b) => a[1].at - b[1].at)[0]
      if (!due) break
      this.timers.delete(due[0])
      this.now = due[1].at
      due[1].fn()
      await nextTick()
      await Promise.resolve()
    }
    this.now = target
  }
}

let clock = new FakeClock()
let hidden = false
const listeners = new Map<string, Set<() => void>>()

Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: {
    setTimeout: (fn: TimerFn, d: number) => clock.setTimeout(fn, d),
    clearTimeout: (id: number) => clock.clearTimeout(id),
  },
})
Object.defineProperty(globalThis, 'document', {
  configurable: true,
  value: {
    get hidden() { return hidden },
    addEventListener(t: string, fn: () => void) {
      if (!listeners.has(t)) listeners.set(t, new Set())
      listeners.get(t)!.add(fn)
    },
    removeEventListener(t: string, fn: () => void) { listeners.get(t)?.delete(fn) },
  },
})
Date.now = () => clock.now

function reset() {
  clock = new FakeClock()
  hidden = false
  listeners.clear()
}

function fireVisibility() {
  for (const fn of listeners.get('visibilitychange') ?? []) fn()
}

const { usePollingScheduler } = await import('../src/composables/usePollingScheduler')

function mount(task: () => Promise<void> | void, interval: number, opts: Record<string, unknown> = {}) {
  const scope = effectScope()
  let api: ReturnType<typeof usePollingScheduler> | undefined
  scope.run(() => { api = usePollingScheduler(task, interval, opts) })
  api!.start()
  return { scope, api: api! }
}

test('a backed-off poll keeps its backoff across a visibility change', async () => {
  reset()
  let fail = true
  const { scope } = mount(() => { if (fail) throw new Error('down') }, 5000, {
    backoffFactor: 4,
    maxIntervalMs: 80000,
    backgroundIntervalMs: 15000,
  })

  // Two failures: 5s -> 20s -> 80s (capped).
  await clock.advance(5000)
  await clock.advance(20000)
  assert.equal(clock.pendingDelay(), 80000, 'expected backoff to reach the cap')

  hidden = true
  // Re-arm while hidden keeps max(80s, 15s) = 80s -- backoff already dominates.
  await clock.advance(80000)
  assert.equal(clock.pendingDelay(), 80000)

  hidden = false
  fireVisibility()
  assert.equal(clock.pendingDelay(), 80000,
    'a backed-off interval must not be shortened by returning to the tab: the ' +
    'backend is still failing and hammering it on focus would make that worse')

  // Recovery must still reset the interval normally.
  fail = false
  await clock.advance(80000)
  assert.equal(clock.pendingDelay(), 5000, 'success resets to the base interval')
  scope.stop()
})

test('background throttling is shortened on return only while healthy', async () => {
  reset()
  const { scope } = mount(() => {}, 5000, { backgroundIntervalMs: 120000 })

  hidden = true
  await clock.advance(5000)
  assert.equal(clock.pendingDelay(), 120000, 'hidden and healthy -> background delay')

  await clock.advance(4000)
  hidden = false
  fireVisibility()

  const pending = clock.pendingDelay()
  assert.ok(pending !== null && pending <= 1000,
    `healthy poll should collapse to the foreground remainder, got ${pending}`)
  scope.stop()
})

test('repeated start() does not stack visibility listeners', async () => {
  reset()
  const { scope, api } = mount(() => {}, 5000, { backgroundIntervalMs: 60000 })
  api.start()
  api.start()
  assert.equal(listeners.get('visibilitychange')?.size, 1,
    'duplicate listeners would re-arm the timer once per start() call')
  scope.stop()
})

test('stop() releases the visibility listener', async () => {
  reset()
  const { scope, api } = mount(() => {}, 5000)
  assert.equal(listeners.get('visibilitychange')?.size, 1)
  api.stop()
  assert.equal(listeners.get('visibilitychange')?.size ?? 0, 0,
    'a stopped scheduler must not keep reacting to tab focus')
  scope.stop()
})
