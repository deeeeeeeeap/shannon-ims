import { getCurrentScope, onScopeDispose, ref } from 'vue'
import { api } from '../stores/auth'

export type EventStreamOptions<T> = {
  path: string
  eventName: string
  query?: Record<string, string | number | boolean | undefined>
  parse: (payload: string) => T
  onEvent: (data: T) => void
  onRawEvent?: (eventName: string, payload: string) => void
  onConnected?: () => void
  reconnectDelayMs?: number
}

export function useEventStream<T>(options: EventStreamOptions<T>) {
  const connected = ref(false)
  const paused = ref(false)
  const lastError = ref('')
  const abortCtrl = ref<AbortController | null>(null)
  const reconnectTimer = ref<number | null>(null)
  let disposed = false

  const queryRef = ref<Record<string, string | number | boolean | undefined>>(options.query || {})

  function clearReconnectTimer() {
    if (reconnectTimer.value !== null) {
      window.clearTimeout(reconnectTimer.value)
      reconnectTimer.value = null
    }
  }

  function buildUrl() {
    const base = api.defaults.baseURL || ''
    const search = new URLSearchParams()
    for (const [k, v] of Object.entries(queryRef.value || {})) {
      if (v == null || v === '') continue
      search.set(k, String(v))
    }
    const qs = search.toString()
    return `${base}${options.path}${qs ? `?${qs}` : ''}`
  }

  async function connect() {
    if (disposed) return
    disconnect()
    if (paused.value) return

    const token = localStorage.getItem('token') || ''
    const controller = new AbortController()
    abortCtrl.value = controller
    const isCurrent = () => abortCtrl.value === controller && !controller.signal.aborted
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined

    try {
      const res = await fetch(buildUrl(), {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: controller.signal
      })
      if (!isCurrent()) {
        await res.body?.cancel()
        return
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      if (!res.body) throw new Error('No stream body')

      connected.value = true
      lastError.value = ''
      options.onConnected?.()

      reader = res.body.getReader()
      const decoder = new TextDecoder('utf-8')
      let buffer = ''
      let eventName = ''
      let dataLines: string[] = []

      while (isCurrent()) {
        const { value, done } = await reader.read()
        // Abort can race with a read that has already settled.
        if (!isCurrent()) return
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        while (isCurrent()) {
          const nl = buffer.indexOf('\n')
          if (nl < 0) break
          let line = buffer.slice(0, nl)
          buffer = buffer.slice(nl + 1)
          if (line.endsWith('\r')) line = line.slice(0, -1)

          if (line === '') {
            const payload = dataLines.join('\n')
            if (eventName === options.eventName) {
              options.onEvent(options.parse(payload))
            }
            if (eventName && isCurrent()) {
              options.onRawEvent?.(eventName, payload)
            }
            eventName = ''
            dataLines = []
            continue
          }
          if (line.startsWith('event:')) {
            eventName = line.slice('event:'.length).trim()
            continue
          }
          if (line.startsWith('data:')) {
            dataLines.push(line.slice('data:'.length).replace(/^\s*/, ''))
            continue
          }
        }
      }
      if (!isCurrent()) return
      connected.value = false
      if (!paused.value) reconnectLater()
    } catch (err: unknown) {
      if (!isCurrent()) return
      connected.value = false
      lastError.value = err instanceof Error ? err.message : String(err)
      reconnectLater()
    } finally {
      // Parser/callback failures also need to release the old response body.
      controller.abort()
      if (reader) {
        await reader.cancel().catch(() => {})
        reader.releaseLock()
      }
      if (abortCtrl.value === controller) abortCtrl.value = null
    }
  }

  function reconnectLater() {
    clearReconnectTimer()
    const delay = options.reconnectDelayMs ?? 5000
    reconnectTimer.value = window.setTimeout(() => {
      reconnectTimer.value = null
      if (!paused.value) void connect()
    }, delay)
  }

  function disconnect() {
    clearReconnectTimer()
    abortCtrl.value?.abort()
    abortCtrl.value = null
    connected.value = false
  }

  function setPaused(v: boolean) {
    paused.value = v
    if (paused.value) disconnect()
    else void connect()
  }

  function setQuery(next: Record<string, string | number | boolean | undefined>) {
    queryRef.value = next || {}
  }

  if (getCurrentScope()) {
    onScopeDispose(() => {
      disposed = true
      disconnect()
    })
  }

  return { connected, paused, lastError, connect, disconnect, setPaused, setQuery }
}
