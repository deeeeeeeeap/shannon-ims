<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  title?: string
  message: string
  details?: string
  statusCode?: number
  requestMethod?: string
  requestUrl?: string
  lastSuccessAt?: number | null
  retryText?: string
}>()
const emit = defineEmits<{
  (e: 'retry'): void
}>()

const metaText = computed(() => {
  const parts: string[] = []
  if (props.statusCode) parts.push(`HTTP ${props.statusCode}`)
  const method = (props.requestMethod || '').toUpperCase()
  if (method && props.requestUrl) parts.push(`${method} ${props.requestUrl}`)
  else if (props.requestUrl) parts.push(String(props.requestUrl))
  if (props.lastSuccessAt) parts.push(`最后成功：${new Date(props.lastSuccessAt).toLocaleString()}`)
  return parts.join(' · ')
})
</script>

<template>
  <div class="p-6 bg-red-50/70 dark:bg-red-500/10 rounded-2xl border border-red-100 dark:border-red-500/20">
    <div class="flex items-start justify-between gap-4">
      <div class="min-w-0">
        <div class="text-sm font-extrabold text-red-700 dark:text-red-300">{{ title || '加载失败' }}</div>
        <div class="mt-1 text-xs text-red-700/80 dark:text-red-200/80 break-words">{{ message }}</div>
        <div v-if="metaText" class="mt-2 text-[11px] text-red-800/60 dark:text-red-100/60 font-mono break-words">
          {{ metaText }}
        </div>
        <div v-if="details" class="mt-2 text-xs font-mono text-red-900/60 dark:text-red-100/60 whitespace-pre-wrap break-words">{{ details }}</div>
      </div>
      <el-button v-if="retryText" type="primary" @click="emit('retry')" class="!border-0">
        {{ retryText }}
      </el-button>
    </div>
  </div>
</template>
