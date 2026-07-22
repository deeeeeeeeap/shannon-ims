<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { api } from '../stores/auth'
import type { CarrierWebsheetInfo } from '../types/api'
import { validateCarrierWebsheetMessage, type CarrierWebsheetCallback } from './carrierWebsheetMessage'

type SecureCarrierWebsheetInfo = CarrierWebsheetInfo & { messageNonce?: string }

const props = defineProps<{
  modelValue: boolean
  websheet: SecureCarrierWebsheetInfo | null
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  done: []
}>()

const loaded = ref(false)
const iframeEl = ref<HTMLIFrameElement | null>(null)
let completing = false

const iframeSrc = computed(() => props.websheet?.embedUrl || '')

watch(() => props.websheet?.id, () => {
  loaded.value = false
})

async function sendCallback(callback: CarrierWebsheetCallback) {
  const id = props.websheet?.id
  const nonce = props.websheet?.messageNonce || ''
  if (!id || !nonce) return
  try {
    await api.post(`/websheets/${id}/callback`, callback, {
      headers: { 'X-Websheet-Nonce': nonce }
    })
  } catch {
    console.error('[CarrierWebsheetDialog] relay callback failed')
  }
}

async function completeWebsheet() {
  if (completing) return
  completing = true
  try {
    const id = props.websheet?.id
    const nonce = props.websheet?.messageNonce || ''
    if (id && nonce) {
      try {
        await api.post(`/websheets/${id}/done`, null, {
          headers: { 'X-Websheet-Nonce': nonce }
        })
      } catch {
        console.error('[CarrierWebsheetDialog] complete websheet failed')
      }
    }
    emit('done')
    emit('update:modelValue', false)
  } finally {
    completing = false
  }
}

function isTerminalCallback(callback: CarrierWebsheetCallback) {
  const value = String(callback.event ?? callback.method ?? callback.resultCode ?? '').toLowerCase()
  if (!value) return true
  return !value.includes('phoneservicesaccountstatuschanged')
}

function onMessage(event: MessageEvent) {
  if (!props.modelValue) return
  if (event.origin !== 'null') return
  if (event.source !== iframeEl.value?.contentWindow) return
  const websheet = props.websheet
  const iframeWindow = iframeEl.value?.contentWindow
  if (!websheet?.id || !websheet.messageNonce || !iframeWindow) return
  const callback = validateCarrierWebsheetMessage(event, {
    iframeWindow,
    sessionId: websheet.id,
    nonce: websheet.messageNonce
  })
  if (!callback) return
  if (isTerminalCallback(callback)) {
    void completeWebsheet()
  } else {
    void sendCallback(callback)
  }
}

onMounted(() => {
  window.addEventListener('message', onMessage)
})
onUnmounted(() => {
  window.removeEventListener('message', onMessage)
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
        sandbox="allow-forms allow-scripts"
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
