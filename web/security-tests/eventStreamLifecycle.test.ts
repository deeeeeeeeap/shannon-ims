import test from 'node:test'
import assert from 'node:assert/strict'
import { effectScope } from 'vue'
import { useEventStream } from '../src/composables/useEventStream'

test('disconnect discards queued events and never reconnects a closed stream', async t => {
  const timers = new Map<number, () => void>()
  let nextTimer = 0
  t.mock.method(globalThis, 'fetch', async () => new Response(body))
  const windowDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'window')
  const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  Object.defineProperty(globalThis, 'window', {
    configurable: true,
    value: {
      setTimeout(fn: () => void) { timers.set(++nextTimer, fn); return nextTimer },
      clearTimeout(id: number) { timers.delete(id) }
    }
  })
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true, value: { getItem: () => null }
  })
  let source!: ReadableStreamDefaultController<Uint8Array>
  const body = new ReadableStream<Uint8Array>({ start(controller) { source = controller } })
  let signalConnected!: () => void
  const connected = new Promise<void>(resolve => { signalConnected = resolve })
  let events = 0
  const stream = useEventStream({
    path: '/logs/stream', eventName: 'log', parse: value => value,
    onEvent: () => { events++ }, onConnected: signalConnected
  })
  t.after(() => {
    stream.disconnect()
    if (windowDescriptor) Object.defineProperty(globalThis, 'window', windowDescriptor)
    else Reflect.deleteProperty(globalThis, 'window')
    if (storageDescriptor) Object.defineProperty(globalThis, 'localStorage', storageDescriptor)
    else Reflect.deleteProperty(globalThis, 'localStorage')
  })
  const completion = stream.connect()
  await connected
  // A read can settle just before AbortController cancellation is observed.
  source.enqueue(new TextEncoder().encode('event: log\ndata: synthetic-event\n\n'))
  source.close()
  stream.disconnect()
  await completion

  assert.equal(events, 0, 'a disconnected consumer must receive no queued event')
  assert.equal(stream.connected.value, false)
  assert.equal(timers.size, 0, 'disconnect must not schedule another connection')
})

test('a disposed view cannot reopen its stream after an awaited history request', async t => {
  const windowDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'window')
  const storageDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  Object.defineProperty(globalThis, 'window', {
    configurable: true, value: { setTimeout: () => 1, clearTimeout: () => {} }
  })
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true, value: { getItem: () => null }
  })
  t.after(() => {
    if (windowDescriptor) Object.defineProperty(globalThis, 'window', windowDescriptor)
    else Reflect.deleteProperty(globalThis, 'window')
    if (storageDescriptor) Object.defineProperty(globalThis, 'localStorage', storageDescriptor)
    else Reflect.deleteProperty(globalThis, 'localStorage')
  })
  let requests = 0
  t.mock.method(globalThis, 'fetch', async () => { requests++; return new Response() })
  const scope = effectScope()
  const stream = scope.run(() => useEventStream({
    path: '/logs/stream', eventName: 'log', parse: value => value, onEvent: () => {}
  }))!
  scope.stop()
  await stream.connect()
  assert.equal(requests, 0)
  assert.equal(stream.connected.value, false)
})
