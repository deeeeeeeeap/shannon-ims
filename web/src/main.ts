import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import { debugCollector } from './debug/collector'
// Element Plus component styles are injected per component by ElementPlusResolver
// (see vite.config.ts importStyle: 'css'), so the 341.8 KB full index.css is not
// imported here. These two are global rather than per-component and still are:
//   base.css      resets and shared tokens every component builds on
//   css-vars.css  the dark-theme variable overrides
import 'element-plus/theme-chalk/base.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

// These three are called as functions (ElMessage 144x, ElMessageBox 19x, ElLoading
// 2x) rather than written as tags, so the component resolver never sees them and
// cannot inject their styles. Without these imports the toasts and confirm dialogs
// render unstyled -- and only at the moment they appear, which is exactly the kind
// of breakage a build check cannot catch.
import 'element-plus/theme-chalk/el-message.css'
import 'element-plus/theme-chalk/el-message-box.css'
import 'element-plus/theme-chalk/el-loading.css'
// el-overlay backs the message box's modal layer.
import 'element-plus/theme-chalk/el-overlay.css'

import './style.css'

let bootFinished = false
let bootErrorOverlay: HTMLDivElement | null = null

function escapeHtml(text: string) {
  return text
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function toErrorText(err: unknown) {
  if (err instanceof Error) {
    return `${err.name}: ${err.message}\n\n${err.stack || ''}`
  }
  if (typeof err === 'string') return err
  try {
    return JSON.stringify(err, null, 2)
  } catch {
    return String(err)
  }
}

function isChunkLoadLikeError(err: unknown) {
  const msg = (err instanceof Error ? err.message : typeof err === 'string' ? err : '') || ''
  return /Loading chunk|ChunkLoadError|dynamically imported module|Importing a module script failed|Failed to fetch dynamically imported module/i.test(
    msg
  )
}

function isScriptLoadErrorEvent(e: Event) {
  const t = e.target
  return t instanceof HTMLScriptElement && !!t.src
}

function showBootError(err: unknown, opts: { force?: boolean } = {}) {
  if (bootFinished && !opts.force) return
  try {
    debugCollector.recordJsError(err, 'boot')
    const text = toErrorText(err)

    if (!bootErrorOverlay) {
      const el = document.createElement('div')
      el.style.position = 'fixed'
      el.style.inset = '0'
      el.style.zIndex = '99999'
      el.style.background = 'rgba(15, 23, 42, 0.92)'
      el.style.color = '#e2e8f0'
      el.style.padding = '24px'
      el.style.fontFamily =
        'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace'
      el.style.overflow = 'auto'
      el.innerHTML = `<div style="max-width: 980px; margin: 0 auto;">
  <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom: 12px;">
    <div style="font-weight: 800; font-size: 18px;">前端异常（Boot Error）</div>
    <div style="display:flex; gap:10px;">
      <button data-action="continue" style="cursor:pointer; border:1px solid rgba(148,163,184,0.25); background: rgba(2, 6, 23, 0.25); color:#e2e8f0; padding:8px 12px; border-radius:10px;">继续使用</button>
      <button data-action="reload" style="cursor:pointer; border:1px solid rgba(148,163,184,0.25); background: rgba(79, 70, 229, 0.25); color:#e2e8f0; padding:8px 12px; border-radius:10px;">刷新页面</button>
    </div>
  </div>
  <div style="opacity: 0.8; margin-bottom: 14px;">建议先尝试刷新；如果仍失败，请把下面内容截图发我（用于定位原因）</div>
  <pre data-role="error-text" style="white-space: pre-wrap; background: rgba(2, 6, 23, 0.6); padding: 16px; border-radius: 12px; border: 1px solid rgba(148,163,184,0.25);"></pre>
</div>`
      el.addEventListener('click', (ev) => {
        const target = ev.target as HTMLElement | null
        const action = target?.getAttribute?.('data-action')
        if (action === 'continue') {
          el.remove()
          bootErrorOverlay = null
        } else if (action === 'reload') {
          window.location.reload()
        }
      })
      bootErrorOverlay = el
      document.body.appendChild(el)
    }

    const pre = bootErrorOverlay.querySelector('pre[data-role="error-text"]') as HTMLPreElement | null
    if (pre) pre.innerHTML = escapeHtml(text)
  } catch {
    // Avoid recursive boot error crashes if overlay rendering itself fails.
  }
}

window.addEventListener('error', (e) => {
  const ev = e as ErrorEvent
  debugCollector.recordJsError(ev.error || ev.message, 'window.error')
  if (isScriptLoadErrorEvent(e)) {
    const t = e.target as HTMLScriptElement
    showBootError(`脚本加载失败：${String(t?.src || '')}`, { force: true })
    return
  }
  if (!bootFinished || isChunkLoadLikeError(ev.error || ev.message)) {
    showBootError(ev.error || ev.message, { force: isChunkLoadLikeError(ev.error || ev.message) })
  }
})

window.addEventListener('unhandledrejection', (e) => {
  const ev = e as PromiseRejectionEvent
  debugCollector.recordJsError(ev.reason, 'unhandledrejection')
  if (!bootFinished || isChunkLoadLikeError(ev.reason)) {
    showBootError(ev.reason, { force: isChunkLoadLikeError(ev.reason) })
  }
})

const app = createApp(App)

app.config.errorHandler = (err) => {
  debugCollector.recordJsError(err, 'vue.errorHandler')
  if (!bootFinished || isChunkLoadLikeError(err)) {
    showBootError(err, { force: isChunkLoadLikeError(err) })
  }
}

// No app.use(ElLoading) here.
//
// It registered the v-loading directive globally, and importing ElLoading from
// 'element-plus' at module scope pulled the entire 757 KB library into the
// first-paint bundle -- on a login screen that renders no el-* component at all.
//
// The directive is used in exactly one place (TrafficAnalysisPanel, itself lazily
// loaded), and ElementPlusResolver already resolves `v-loading` automatically: see
// the GlobalDirectives entry in src/components.d.ts, which the plugin generates.
// So the registration was redundant and the import cost was the only effect.
app.use(createPinia())
app.use(router)

router.onError((err) => {
  showBootError(err, { force: true })
})

app.mount('#app')
bootFinished = true
