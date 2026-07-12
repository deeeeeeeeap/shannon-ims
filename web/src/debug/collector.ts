import { ref } from 'vue'
import { toAppError } from '../services/http'

export type DebugRouteEvent = {
  ts: number
  from?: string
  to?: string
  name?: string
}

export type DebugApiError = {
  ts: number
  status?: number
  method?: string
  url?: string
  message: string
}

export type DebugJsError = {
  ts: number
  message: string
  stack?: string
  source?: string
}

export type DebugAuthEvent = {
  ts: number
  kind: '401_redirect'
  redirectTo?: string
}

function pushLimited<T>(target: { value: T[] }, item: T, limit = 50) {
  const next = target.value.concat([item])
  target.value = next.length > limit ? next.slice(next.length - limit) : next
}

const routes = ref<DebugRouteEvent[]>([])
const apiErrors = ref<DebugApiError[]>([])
const jsErrors = ref<DebugJsError[]>([])
const authEvents = ref<DebugAuthEvent[]>([])
const openPanelRequestAt = ref<number | null>(null)

type RouteLike = {
  fullPath?: string
  name?: string | symbol | null
}

function recordRoute(to: RouteLike | null | undefined, from: RouteLike | null | undefined) {
  pushLimited(routes, {
    ts: Date.now(),
    from: from?.fullPath,
    to: to?.fullPath,
    name: to?.name ? String(to.name) : undefined
  })
}

function recordApiError(err: unknown) {
  const parsed = toAppError(err)
  pushLimited(apiErrors, {
    ts: Date.now(),
    status: parsed.status,
    method: parsed.method,
    url: parsed.url,
    message: String(parsed.message || 'API 请求失败')
  })
}

function recordJsError(err: unknown, source?: string) {
  if (err instanceof Error) {
    pushLimited(jsErrors, {
      ts: Date.now(),
      message: `${err.name}: ${err.message}`,
      stack: err.stack || undefined,
      source
    })
    return
  }

  pushLimited(jsErrors, {
    ts: Date.now(),
    message: typeof err === 'string' ? err : JSON.stringify(err),
    source
  })
}

function recordAuthEvent(e: DebugAuthEvent) {
  pushLimited(authEvents, e)
}

function clearAll() {
  routes.value = []
  apiErrors.value = []
  jsErrors.value = []
  authEvents.value = []
}

function requestOpenPanel() {
  openPanelRequestAt.value = Date.now()
}

function snapshot() {
  return {
    ts: Date.now(),
    location: typeof window !== 'undefined' ? window.location.href : '',
    routes: routes.value,
    apiErrors: apiErrors.value,
    jsErrors: jsErrors.value
  }
}

function sanitizeString(s: string) {
  let out = s
  out = out.replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer ***')
  out = out.replace(/\b(1)\d{6}(\d{4})\b/g, '$1******$2')
  out = out.replace(/\b\d{4,6}:[A-Za-z0-9._-]{16,}\b/g, '***:***')
  return out
}

function sanitizeAny(v: unknown, key?: string): unknown {
  if (v == null) return v
  const k = String(key || '')
  if (/token|secret|password/i.test(k)) return '***'
  if (typeof v === 'string') return sanitizeString(v)
  if (typeof v === 'number' || typeof v === 'boolean') return v
  if (Array.isArray(v)) return v.map(x => sanitizeAny(x))
  if (typeof v === 'object') {
    const obj = v as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const [kk, vv] of Object.entries(obj)) {
      out[kk] = sanitizeAny(vv, kk)
    }
    return out
  }
  return String(v)
}

function sanitizedSnapshot() {
  return sanitizeAny({
    ts: Date.now(),
    location: typeof window !== 'undefined' ? window.location.href : '',
    routes: routes.value,
    apiErrors: apiErrors.value,
    jsErrors: jsErrors.value,
    authEvents: authEvents.value
  })
}

export const debugCollector = {
  routes,
  apiErrors,
  jsErrors,
  authEvents,
  openPanelRequestAt,
  requestOpenPanel,
  recordAuthEvent,
  recordRoute,
  recordApiError,
  recordJsError,
  clearAll,
  snapshot,
  sanitizedSnapshot
}
