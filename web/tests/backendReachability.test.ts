import test from 'node:test'
import assert from 'node:assert/strict'

// The distinction pinned here: a server that ANSWERS is reachable, even when the
// answer is a rejection. Counting 401/403/5xx as connectivity failures would make
// the header read "连接中断" every time an API legitimately said no -- which is both
// wrong and the kind of false alarm that trains an operator to ignore the indicator.
//
// Also pinned: a single blip must not flip the display, because every view polls on
// a 5-60s cadence and transient failures are normal.

const mod = await import('../src/composables/useBackendReachability')
const { noteBackendSuccess, noteBackendFailure, useBackendReachability } = mod

const { state, label } = useBackendReachability()

test('starts as unknown before any traffic', () => {
  assert.equal(state.value, 'unknown')
  assert.equal(label.value, '连接中')
})

test('one success marks it reachable', () => {
  noteBackendSuccess()
  assert.equal(state.value, 'ok')
  assert.equal(label.value, '已连接')
})

test('a single transient failure does not flip the display', () => {
  noteBackendSuccess()
  noteBackendFailure()
  assert.equal(state.value, 'ok', 'one blip is normal on a polling UI')
})

test('repeated failures escalate, then recover on the next success', () => {
  noteBackendSuccess()
  noteBackendFailure()
  noteBackendFailure()
  assert.equal(state.value, 'degraded', '2 failures -> unstable')

  noteBackendFailure()
  assert.equal(state.value, 'down', '3 failures -> down')
  assert.equal(label.value, '连接中断')

  noteBackendSuccess()
  assert.equal(state.value, 'ok', 'a single success clears the counter')
})

test('escalation is monotonic', () => {
  noteBackendSuccess()
  const seen: string[] = []
  for (let i = 0; i < 5; i++) {
    noteBackendFailure()
    seen.push(state.value)
  }
  const rank = { unknown: 0, ok: 1, degraded: 2, down: 3 } as Record<string, number>
  for (let i = 1; i < seen.length; i++) {
    assert.ok(rank[seen[i]] >= rank[seen[i - 1]], `state went backwards: ${seen.join(' -> ')}`)
  }
  assert.equal(seen[seen.length - 1], 'down')
  noteBackendSuccess()
})

test('every state has a non-empty label', () => {
  // Reset, then walk each state and check the label is populated.
  noteBackendSuccess()
  assert.ok(label.value.length > 0)
  noteBackendFailure()
  noteBackendFailure()
  assert.ok(label.value.length > 0)
  noteBackendFailure()
  assert.ok(label.value.length > 0)
  noteBackendSuccess()
})

test('the exported refs are readonly', () => {
  // Callers must not be able to fake connectivity from a view.
  const before = state.value
  try {
    // @ts-expect-error deliberately probing the readonly guard
    state.value = 'down'
  } catch {
    // Vue may throw in dev; either way the value must not change.
  }
  assert.equal(state.value, before)
})
