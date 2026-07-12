<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { debugCollector } from '../debug/collector'
import { copyToClipboard } from '../utils/clipboard'

const props = defineProps<{
  modelValue: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
}>()

const open = computed({
  get: () => props.modelValue,
  set: (v: boolean) => emit('update:modelValue', v)
})

const currentHref = computed(() => {
  return typeof window !== 'undefined' ? window.location.href : ''
})

const autoOpen = ref(false)

onMounted(() => {
  autoOpen.value = localStorage.getItem('debug_panel_auto_open') === '1'
})

watch(
  () => autoOpen.value,
  (v) => {
    localStorage.setItem('debug_panel_auto_open', v ? '1' : '0')
  }
)

function fmtTs(ts: number) {
  return new Date(ts).toLocaleString()
}

async function copySnapshot() {
  await copyToClipboard(JSON.stringify(debugCollector.sanitizedSnapshot(), null, 2), '已复制诊断信息')
}

function downloadSnapshot() {
  try {
    const now = new Date()
    const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`
    const blob = new Blob([JSON.stringify(debugCollector.sanitizedSnapshot(), null, 2)], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `debug-${stamp}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    ElMessage.success('已下载诊断文件')
  } catch {
    ElMessage.error('导出失败')
  }
}

function clearAll() {
  debugCollector.clearAll()
  ElMessage.success('已清空')
}
</script>

<template>
  <el-drawer v-model="open" direction="rtl" size="520px" title="诊断面板">
    <div class="flex items-center justify-between gap-2 mb-4">
      <div class="text-xs text-gray-500 dark:text-gray-400 font-mono truncate">
        {{ currentHref }}
      </div>
      <div class="flex items-center gap-2">
        <div class="flex items-center gap-2 px-2">
          <div class="text-xs text-gray-500 dark:text-gray-400">错误自动弹出</div>
          <el-switch v-model="autoOpen" />
        </div>
        <el-button @click="clearAll" class="!border-0 !bg-white/70 dark:!bg-white/5">清空</el-button>
        <el-button @click="downloadSnapshot" class="!border-0 !bg-white/70 dark:!bg-white/5">导出</el-button>
        <el-button type="primary" @click="copySnapshot" class="!border-0">复制</el-button>
      </div>
    </div>

    <div class="space-y-6">
      <div class="ui-panel-muted p-4">
        <div class="text-sm font-extrabold text-gray-900 dark:text-white mb-2">最近路由</div>
        <div v-if="debugCollector.routes.value.length === 0" class="text-xs text-gray-400">暂无记录</div>
        <div v-else class="space-y-2 max-h-[220px] overflow-auto">
          <div v-for="r in debugCollector.routes.value.slice().reverse()" :key="r.ts" class="text-xs font-mono">
            <div class="text-gray-500">{{ fmtTs(r.ts) }}</div>
            <div class="text-gray-800 dark:text-gray-200 break-words">
              {{ r.from || '-' }} → {{ r.to || '-' }} <span v-if="r.name" class="text-gray-400">({{ r.name }})</span>
            </div>
          </div>
        </div>
      </div>

      <div class="ui-panel-muted p-4">
        <div class="text-sm font-extrabold text-gray-900 dark:text-white mb-2">最近 API 错误</div>
        <div v-if="debugCollector.apiErrors.value.length === 0" class="text-xs text-gray-400">暂无记录</div>
        <div v-else class="space-y-2 max-h-[260px] overflow-auto">
          <div v-for="a in debugCollector.apiErrors.value.slice().reverse()" :key="a.ts" class="text-xs font-mono">
            <div class="text-gray-500">{{ fmtTs(a.ts) }}</div>
            <div class="text-gray-800 dark:text-gray-200 break-words">
              <span v-if="a.status">HTTP {{ a.status }} · </span>
              <span v-if="a.method">{{ String(a.method).toUpperCase() }} </span>
              <span v-if="a.url">{{ a.url }}</span>
            </div>
            <div class="text-gray-600 dark:text-gray-300 break-words">{{ a.message }}</div>
          </div>
        </div>
      </div>

      <div class="ui-panel-muted p-4">
        <div class="text-sm font-extrabold text-gray-900 dark:text-white mb-2">最近前端错误</div>
        <div v-if="debugCollector.jsErrors.value.length === 0" class="text-xs text-gray-400">暂无记录</div>
        <div v-else class="space-y-2 max-h-[260px] overflow-auto">
          <div v-for="j in debugCollector.jsErrors.value.slice().reverse()" :key="j.ts" class="text-xs font-mono">
            <div class="text-gray-500">{{ fmtTs(j.ts) }} <span v-if="j.source" class="text-gray-400">· {{ j.source }}</span></div>
            <div class="text-gray-800 dark:text-gray-200 break-words">{{ j.message }}</div>
            <div v-if="j.stack" class="text-gray-600 dark:text-gray-300 whitespace-pre-wrap break-words">{{ j.stack }}</div>
          </div>
        </div>
      </div>

      <div class="ui-panel-muted p-4">
        <div class="text-sm font-extrabold text-gray-900 dark:text-white mb-2">鉴权事件</div>
        <div v-if="debugCollector.authEvents.value.length === 0" class="text-xs text-gray-400">暂无记录</div>
        <div v-else class="space-y-2 max-h-[160px] overflow-auto">
          <div v-for="e in debugCollector.authEvents.value.slice().reverse()" :key="e.ts" class="text-xs font-mono">
            <div class="text-gray-500">{{ fmtTs(e.ts) }}</div>
            <div class="text-gray-800 dark:text-gray-200 break-words">
              {{ e.kind }} <span v-if="e.redirectTo" class="text-gray-400">· redirect={{ e.redirectTo }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </el-drawer>
</template>
