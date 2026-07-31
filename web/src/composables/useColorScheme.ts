import { onScopeDispose, readonly, ref } from 'vue'

// Single source of truth for "is the UI currently dark".
//
// The theme is expressed as the `dark` class on <html> (set by index.html's inline
// script before first paint, then toggled by App.vue). Components that render to a
// canvas rather than to DOM -- ECharts being the case that forced this -- cannot
// read CSS variables or dark: utilities, so they need the boolean itself.
//
// Implemented as one module-level MutationObserver shared by every caller rather
// than one observer per component: the observed attribute is global, so per-caller
// observers would all fire on the same mutation and do identical work.

const isDark = ref(readCurrent())

function readCurrent() {
  if (typeof document === 'undefined') return false
  return document.documentElement.classList.contains('dark')
}

let observer: MutationObserver | null = null
let refCount = 0

function start() {
  if (observer || typeof document === 'undefined') return
  observer = new MutationObserver(() => {
    isDark.value = readCurrent()
  })
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class'],
  })
}

function stop() {
  observer?.disconnect()
  observer = null
}

export function useColorScheme() {
  refCount++
  start()
  onScopeDispose(() => {
    refCount--
    // Only tear the observer down once nothing is watching; a component
    // unmounting while others are still mounted must not blind the rest.
    if (refCount <= 0) {
      refCount = 0
      stop()
    }
  })
  return { isDark: readonly(isDark) }
}
