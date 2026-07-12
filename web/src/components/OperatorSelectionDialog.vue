<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { devicesService } from '../services/devices'
import type { OperatorCandidate, OperatorSelection, OperatorSelectionRAT } from '../types/api'
import { useDevicesStore } from '../stores/devices'
import { ElMessage } from 'element-plus'

const props = defineProps<{
  modelValue: boolean
  deviceId: string
}>()

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  'updated': []
}>()

const devicesStore = useDevicesStore()
const loading = ref(false)
const currentSelection = ref<OperatorSelection | null>(null)
const lastNotifiedScanKey = ref('')

const scanState = computed(() => {
  if (!props.deviceId) return null
  return devicesStore.getOperatorScan(props.deviceId)
})
const scanning = computed(() => scanState.value?.status === 'running')
const candidates = computed<OperatorCandidate[]>(() => scanState.value?.candidates || [])
const scanMessage = computed(() => scanState.value?.message || '')
const scanError = computed(() => (scanState.value?.retryable ? '' : (scanState.value?.error || '')))
const scanRetryable = computed(() => !!scanState.value?.retryable)

function handleDialogModelUpdate(value: boolean) {
  emit('update:modelValue', value)
}

function firstCandidateRAT(candidate: OperatorCandidate): OperatorSelectionRAT | undefined {
  return candidate.rats?.find(rat => !!rat)
}

function ratDisplay(candidate: OperatorCandidate) {
  const rats = candidate.rats?.filter(Boolean) || []
  return rats.length > 0 ? rats.map(rat => rat.toUpperCase()).join(' / ') : '--'
}

const loadCurrent = async () => {
  if (!props.deviceId) return
  loading.value = true
  try {
    const res = await devicesService.getOperatorSelection(props.deviceId)
    if (!res.ok) throw new Error(res.error.message)
    currentSelection.value = res.data
  } catch (e: any) {
    ElMessage.error(e.message || '加载当前配置失败')
  } finally {
    loading.value = false
  }
}

const doScan = async () => {
  if (!props.deviceId || scanning.value) return
  try {
    await devicesStore.startOperatorScan(props.deviceId)
  } catch (e: any) {
    ElMessage.error(e.message || '扫描网络失败')
  }
}

const setModeAuto = async () => {
  loading.value = true
  try {
    const res = await devicesService.setOperatorSelection(props.deviceId, { mode: 'automatic' })
    if (!res.ok) throw new Error(res.error.message)
    ElMessage.success('已恢复自动选网')
    emit('updated')
    await loadCurrent()
  } catch (e: any) {
    ElMessage.error(e.message || '设置失败')
  } finally {
    loading.value = false
  }
}

const setModeManual = async (candidate: OperatorCandidate) => {
  loading.value = true
  try {
    const rat = firstCandidateRAT(candidate)
    const res = await devicesService.setOperatorSelection(props.deviceId, {
      mode: 'manual',
      plmn: candidate.plmn,
      includes_pcs_digit: candidate.includes_pcs_digit,
      rat
    })
    if (!res.ok) throw new Error(res.error.message)
    ElMessage.success(`已锁定网络 ${candidate.plmn}`)
    emit('updated')
    await loadCurrent()
  } catch (e: any) {
    ElMessage.error(e.message || '设置失败')
  } finally {
    loading.value = false
  }
}

watch(() => props.modelValue, (val) => {
  if (val) {
    loadCurrent()
    if (props.deviceId) {
      void devicesStore.resumeOperatorScan(props.deviceId)
    }
  }
})

watch(scanState, (next) => {
  if (!next || !props.modelValue) return
  const notifyKey = `${next.scan_id}:${next.status}`
  if (notifyKey === lastNotifiedScanKey.value) return
  if (next.status === 'complete') {
    ElMessage.success('运营商扫描完成')
  } else if (next.status === 'failed' && next.retryable) {
    ElMessage.warning(next.message || '扫描超时或模组忙，请稍后重试')
  }
  lastNotifiedScanKey.value = notifyKey
})
</script>

<template>
  <el-dialog
    :model-value="modelValue"
    @update:model-value="handleDialogModelUpdate"
    title="运营商网络选择"
    width="min(500px, 92vw)"
    class="glass-modal"
  >
    <div class="mt-2 text-sm text-gray-600 dark:text-gray-300">
      <!-- 当前状态 -->
      <div class="bg-gray-50 dark:bg-white/5 rounded-lg p-4 mb-4 border border-gray-100 dark:border-white/5">
        <div class="flex justify-between items-center mb-2">
          <span class="font-medium text-gray-700 dark:text-gray-200">当前模式</span>
          <span class="px-2 py-0.5 rounded text-xs font-medium"            :class="currentSelection?.mode === 'automatic' ? 'bg-blue-100 text-blue-700 dark:bg-blue-500/20 dark:text-blue-300' : 'bg-amber-100 text-amber-700 dark:bg-amber-500/20 dark:text-amber-300'">
            {{ currentSelection?.mode === 'automatic' ? '自动' : '手动锁定' }}
          </span>
        </div>
        <div v-if="currentSelection?.mode === 'manual'" class="flex justify-between items-center">
          <span class="text-gray-500">已锁定 PLMN</span>
          <span class="font-mono text-gray-900 dark:text-white">{{ currentSelection.plmn || '--' }}</span>
        </div>
      </div>

      <div class="flex gap-3 mb-4">
        <el-button @click="doScan" :loading="scanning" class="flex-1" type="primary" plain>
          {{ scanning ? '扫描中...' : '扫描可用网络' }}
        </el-button>
        <el-button @click="setModeAuto" :disabled="loading || currentSelection?.mode === 'automatic'" class="flex-1">
          恢复自动选网
        </el-button>
      </div>

      <div v-if="scanning || scanMessage || scanError" class="mb-4 rounded-lg border px-3 py-2 text-xs"
        :class="scanError ? (scanRetryable ? 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-300' : 'border-red-200 bg-red-50 text-red-700 dark:border-red-500/20 dark:bg-red-500/10 dark:text-red-300') : 'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-500/20 dark:bg-blue-500/10 dark:text-blue-300'">
        {{ scanError || scanMessage }}
      </div>

      <!-- 扫描结果列表 -->
      <div v-if="candidates.length > 0" class="border border-gray-200 dark:border-white/10 rounded-lg overflow-hidden divide-y divide-gray-200 dark:divide-white/10 max-h-[300px] overflow-y-auto">
        <div v-for="c in candidates" :key="`${c.plmn}-${ratDisplay(c)}`"          class="p-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-white/5 transition-colors cursor-pointer group"
          @click="setModeManual(c)"
        >
          <div>
            <div class="font-medium text-gray-900 dark:text-white flex items-center gap-2">
              {{ c.operator_name || c.short_name || '未知网络' }}
              <span v-if="c.status === 'current'" class="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-300 font-bold border border-emerald-200 dark:border-emerald-500/30">当前</span>
              <span v-else-if="c.status === 'forbidden'" class="text-[10px] px-1.5 py-0.5 rounded-full bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-300 font-bold border border-red-200 dark:border-red-500/30">禁用</span>
            </div>
            <div class="text-xs text-gray-500 dark:text-gray-400 font-mono mt-0.5">
              {{ c.plmn }} • {{ ratDisplay(c) }}
            </div>
          </div>
          <div>
            <el-button type="primary" link size="small" class="opacity-0 group-hover:opacity-100 transition-opacity">
              锁定
            </el-button>
          </div>
        </div>
      </div>
      <div v-else-if="scanning" class="py-8 text-center text-gray-500 flex flex-col items-center justify-center space-y-3">
        <span>正在搜索周围网络，这可能需要 1-3 分钟...</span>
      </div>
      <div v-else-if="scanRetryable" class="py-8 text-center text-amber-600 dark:text-amber-300 flex flex-col items-center justify-center space-y-3">
        <span>{{ scanMessage || '扫描超时或模组忙，请稍后重试' }}</span>
      </div>
    </div>
  </el-dialog>
</template>
