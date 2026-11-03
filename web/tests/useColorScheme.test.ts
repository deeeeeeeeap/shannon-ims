import test from 'node:test'
import assert from 'node:assert/strict'
import { effectScope, nextTick } from 'vue'

// useColorScheme shares ONE MutationObserver across all callers and tears it down
// by reference count. The refcount is the part worth testing: an off-by-one there
// disconnects the observer while components are still mounted, and the failure is
// silent -- the chart simply stops following the theme, with no error anywhere.

type ObserverInit = { attributes?: boolean; attributeFilter?: string[] }

let liveObservers = 0
let connectCount = 0
let notify: (() => void) | null = null

class FakeMutationObserver {
  constructor(private cb: () => void) {}
  observe(_target: unknown, _init?: ObserverInit) {
    liveObservers++
    connectCount++
    notify = () => this.cb()
  }
  disconnect() {
    liveObservers--
    notify = null
  }
  takeRecords() {
    return []
  }
}

const classList = new Set<string>()
const html = {
  classList: {
    contains: (c: string) => classList.has(c),
  },
}

Object.defineProperty(globalThis, 'MutationObserver', {
  configurable: true,
  value: FakeMutationObserver,
})
Object.defineProperty(globalThis, 'document', {
  configurable: true,
  value: { documentElement: html },
})

const { useColorScheme } = await import('../src/composables/useColorScheme')

test('reports the current html.dark state on first call', () => {
  const scope = effectScope()
  const dark = scope.run(() => useColorScheme().isDark)
  assert.equal(dark?.value, false, 'should start light when html has no dark class')
  scope.stop()
})

test('tracks class mutations after the observer fires', async () => {
  const scope = effectScope()
  const dark = scope.run(() => useColorScheme().isDark)

  classList.add('dark')
  notify?.()
  await nextTick()
  assert.equal(dark?.value, true, 'should follow html.dark being added')

  classList.delete('dark')
  notify?.()
  await nextTick()
  assert.equal(dark?.value, false, 'should follow html.dark being removed')

  scope.stop()
})

test('two concurrent callers share a single observer', () => {
  const before = connectCount
  const a = effectScope()
  const b = effectScope()
  a.run(() => useColorScheme())
  b.run(() => useColorScheme())

  assert.equal(connectCount - before, 1, 'second caller must reuse the observer')
  assert.equal(liveObservers, 1)

  a.stop()
  b.stop()
})

test('observer survives one caller unmounting while another is still active', async () => {
  const a = effectScope()
  const b = effectScope()
  a.run(() => useColorScheme())
  const dark = b.run(() => useColorScheme().isDark)

  a.stop()
  assert.equal(liveObservers, 1, 'observer must stay connected for the remaining caller')

  // The surviving caller must still see updates.
  classList.add('dark')
  notify?.()
  await nextTick()
  assert.equal(dark?.value, true, 'remaining caller stopped receiving updates')

  classList.delete('dark')
  notify?.()
  await nextTick()

  b.stop()
  assert.equal(liveObservers, 0, 'observer must disconnect once nothing is watching')
})

test('re-subscribing after a full teardown reconnects', () => {
  const before = connectCount
  const scope = effectScope()
  scope.run(() => useColorScheme())
  assert.equal(connectCount - before, 1, 'should reconnect after refcount hit zero')
  assert.equal(liveObservers, 1)
  scope.stop()
  assert.equal(liveObservers, 0)
})
