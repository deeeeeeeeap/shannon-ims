<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../stores/auth'
import type { CarrierWebsheetInfo } from '../types/api'

const props = defineProps<{
  modelValue: boolean
  websheet: CarrierWebsheetInfo | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  done: []
}>()

const loaded = ref(false)
const iframeEl = ref<HTMLIFrameElement | null>(null)
let completing = false
let websheetChannel: BroadcastChannel | null = null

const iframeSrc = computed(() => props.websheet?.embedUrl || '')
const websheetToken = computed(() => {
  const raw = props.websheet?.embedUrl || ''
  if (!raw) return ''
  try {
    const url = new URL(raw, window.location.origin)
    return url.searchParams.get('token') || ''
  } catch {
    return ''
  }
})

watch(() => props.websheet?.id, () => {
  loaded.value = false
})

async function sendCallback(callback: unknown) {
  const id = props.websheet?.id
  if (!id || !callback || typeof callback !== 'object') return
  try {
    await api.post(`/websheets/${id}/callback`, callback)
  } catch (err) {
    console.error('[CarrierWebsheetDialog] relay callback failed:', err)
  }
}

async function completeWebsheet() {
  if (completing) return
  completing = true
  try {
    const id = props.websheet?.id
    if (id) {
      try {
        await api.post(`/websheets/${id}/done`)
      } catch (err) {
        console.error('[CarrierWebsheetDialog] complete websheet failed:', err)
      }
    }
    emit('done')
    emit('update:modelValue', false)
  } finally {
    completing = false
  }
}

function isTerminalCallback(callback: unknown) {
  if (!callback || typeof callback !== 'object') return true
  const record = callback as { event?: unknown; method?: unknown; resultCode?: unknown }
  const value = String(record.event ?? record.method ?? record.resultCode ?? '').toLowerCase()
  if (!value) return true
  return !value.includes('phoneservicesaccountstatuschanged')
}

function isCurrentWebsheetMessage(data: unknown): data is { type: string; token?: unknown; callback?: unknown } {
  if (!data || typeof data !== 'object') return false
  const record = data as { type?: unknown; token?: unknown }
  if (record.type !== 'vohive-websheet-callback') return false
  const currentToken = websheetToken.value
  const incomingToken = typeof record.token === 'string' ? record.token : ''
  if (currentToken && incomingToken && incomingToken !== currentToken) return false
  return true
}

function handleShellMessage(data: unknown) {
  if (!props.modelValue || !isCurrentWebsheetMessage(data)) return
  if (isTerminalCallback(data.callback)) {
    void completeWebsheet()
  } else {
    void sendCallback(data.callback)
  }
}

function onMessage(event: MessageEvent) {
  handleShellMessage(event.data)
}

function onStorage(event: StorageEvent) {
  if (event.key !== 'vohive-websheet-complete' || !event.newValue) return
  try {
    handleShellMessage(JSON.parse(event.newValue))
  } catch {
    // Ignore stale or malformed completion notifications.
  }
}

onMounted(() => {
  window.addEventListener('message', onMessage)
  window.addEventListener('storage', onStorage)
  try {
    websheetChannel = new BroadcastChannel('vohive-websheet')
    websheetChannel.onmessage = event => handleShellMessage(event.data)
  } catch {
    websheetChannel = null
  }
})
onUnmounted(() => {
  window.removeEventListener('message', onMessage)
  window.removeEventListener('storage', onStorage)
  websheetChannel?.close()
  websheetChannel = null
})
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    :title="websheet?.title || 'E911地址'"
    width="min(390px, 94vw)"
    destroy-on-close
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="websheet-frame-shell relative overflow-hidden rounded border border-gray-200 dark:border-gray-700">
      <div v-if="!loaded" class="absolute inset-0 z-10 flex items-center justify-center bg-white/80 text-sm text-gray-500 dark:bg-gray-900/80">
        加载中...
      </div>
      <iframe
        v-if="iframeSrc"
        ref="iframeEl"
        :src="iframeSrc"
        class="block h-full w-full border-0"
        sandbox="allow-forms allow-same-origin allow-scripts allow-popups allow-popups-to-escape-sandbox"
        @load="loaded = true"
      />
    </div>
  </el-dialog>
</template>

<style scoped>
.websheet-frame-shell {
  height: min(680px, 78vh);
}

@media (max-width: 640px) {
  .websheet-frame-shell {
    height: min(620px, calc(100vh - 140px));
  }
}
</style>
