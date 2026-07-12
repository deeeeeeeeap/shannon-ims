<script setup lang="ts">
import { computed } from 'vue'
import { copyToClipboard } from '../utils/clipboard'

const props = defineProps<{
  label: string
  value?: unknown
  copyable?: boolean
  monospace?: boolean
  placeholder?: string
  sensitive?: boolean // 加密显示（打码）
}>()

const displayValue = computed(() => {
  const raw = props.value
  const s = raw == null ? '' : String(raw)
  const trimmed = s.trim()
  return trimmed || props.placeholder || '--'
})

const canCopy = computed(() => {
  if (!props.copyable) return false
  const v = displayValue.value
  return !!v && v !== '--' && v !== '---'
})

const titleValue = computed(() => {
  if (props.sensitive) return ''
  const v = displayValue.value
  return v === '--' || v === '---' ? '' : v
})

async function copy() {
  if (!canCopy.value) return
  await copyToClipboard(displayValue.value, '已复制')
}
</script>

<template>
  <div class="flex w-full min-w-0 items-center justify-between gap-3 overflow-hidden">
    <span class="text-gray-500 shrink-0 whitespace-nowrap">{{ label }}</span>
    <span
      class="block min-w-0 max-w-full flex-1 truncate text-right"
      :class="[
        monospace ? 'font-mono' : '',
        canCopy ? 'cursor-pointer hover:underline' : '',
        sensitive ? 'blur-sm select-none transition-all' : ''
      ]"
      :title="titleValue"
      @click="copy"
    >
      <slot>{{ displayValue }}</slot>
    </span>
  </div>
</template>
