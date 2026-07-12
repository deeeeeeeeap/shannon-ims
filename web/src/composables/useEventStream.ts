import { ref } from 'vue'
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
    disconnect()
    if (paused.value) return

    const token = localStorage.getItem('token') || ''
    const controller = new AbortController()
    abortCtrl.value = controller

    try {
      const res = await fetch(buildUrl(), {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}`, Accept: 'text/event-stream' },
        signal: controller.signal
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      if (!res.body) throw new Error('No stream body')

      connected.value = true
      lastError.value = ''
      options.onConnected?.()

      const reader = res.body.getReader()
      const decoder = new TextDecoder('utf-8')
      let buffer = ''
      let eventName = ''
      let dataLines: string[] = []

      while (true) {
        const { value, done } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        while (true) {
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
            if (eventName) {
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
      connected.value = false
      if (!paused.value) reconnectLater()
    } catch (err: unknown) {
      if (controller.signal.aborted) return
      connected.value = false
      lastError.value = err instanceof Error ? err.message : String(err)
      reconnectLater()
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

  return { connected, paused, lastError, connect, disconnect, setPaused, setQuery }
}
