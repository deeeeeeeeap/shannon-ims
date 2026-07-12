import { ref, watch } from 'vue'
import type { Ref } from 'vue'

const SENSITIVE_VISIBILITY_STORAGE_KEY = 'vohive_show_sensitive'

function readSensitiveVisibility(): boolean {
  try {
    if (typeof window === 'undefined') return false
    return window.localStorage.getItem(SENSITIVE_VISIBILITY_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

function writeSensitiveVisibility(visible: boolean) {
  try {
    if (typeof window === 'undefined') return
    window.localStorage.setItem(SENSITIVE_VISIBILITY_STORAGE_KEY, visible ? '1' : '0')
  } catch {
    // Ignore restricted-storage environments; the in-memory ref still works.
  }
}

const sensitiveVisible = ref(readSensitiveVisibility())
let persistenceStarted = false

function startSensitiveVisibilityPersistence() {
  if (persistenceStarted) return
  persistenceStarted = true
  watch(sensitiveVisible, (visible) => writeSensitiveVisibility(visible))
}

export function useSensitiveVisibility(): Ref<boolean> {
  startSensitiveVisibilityPersistence()
  return sensitiveVisible
}
