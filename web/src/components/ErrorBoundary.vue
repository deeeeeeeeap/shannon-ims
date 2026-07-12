<script setup lang="ts">
import { onErrorCaptured, ref } from 'vue'
import ErrorState from './ErrorState.vue'
import { debugCollector } from '../debug/collector'

const props = defineProps<{
  title?: string
  retryText?: string
}>()

const errorMessage = ref<string | null>(null)
const errorDetails = ref<string | null>(null)
const renderKey = ref(0)

function reset() {
  errorMessage.value = null
  errorDetails.value = null
  renderKey.value += 1
}

onErrorCaptured((err) => {
  debugCollector.recordJsError(err, 'vue.errorCaptured')
  if (typeof window !== 'undefined') {
    try {
      if (localStorage.getItem('debug_panel_auto_open') === '1') {
        debugCollector.requestOpenPanel()
      }
    } catch {
      // Ignore localStorage access failures in restricted environments.
    }
  }
  if (err instanceof Error) {
    errorMessage.value = `${err.name}: ${err.message}`
    errorDetails.value = err.stack || null
  } else {
    errorMessage.value = typeof err === 'string' ? err : JSON.stringify(err)
    errorDetails.value = null
  }
  return false
})
</script>

<template>
  <ErrorState
    v-if="errorMessage"
    :title="props.title || '页面渲染失败'"
    :message="errorMessage"
    :details="errorDetails || undefined"
    :retry-text="props.retryText || '重试渲染'"
    @retry="reset"
  />
  <div v-else :key="renderKey">
    <slot />
  </div>
</template>
