<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Code24Regular, Warning24Regular } from '@vicons/fluent'
import { AT_TEMPLATES } from '../constants/atTemplates'
import { devicesService } from '../services/devices'

const props = defineProps<{
  deviceId: string
  backendMode?: string
  atPort?: string
  running?: boolean
}>()

const atCmd = ref('')
const atTemplate = ref('')
const atTimeoutMs = ref(10000)
const atSending = ref(false)
const atHistory = ref<Array<{ ts: number; cmd: string; ok: boolean; response: string }>>([])

const atTemplates = AT_TEMPLATES
const hasATPort = computed(() => String(props.atPort || '').trim().length > 0)
const canUseATTerminal = computed(() => Boolean(props.running) && hasATPort.value)
const unavailableTitle = computed(() => {
  if (!props.running) return '当前设备未运行'
  if (!hasATPort.value) return '当前设备没有可用 AT 口'
  return 'AT 终端暂不可用'
})
const unavailableDescription = computed(() => {
  if (!props.running) {
    return '设备当前未启动，AT 终端暂时不可用。待设备运行后，如果存在可用的 AT 口，即可在这里直接发送 AT 指令。'
  }
  if (!hasATPort.value && props.backendMode === 'qmi') {
    return '设备当前处于纯 QMI 模式，但没有解析到可用的 AT 口，因此无法提供 AT 串口终端。'
  }
  if (!hasATPort.value) {
    return '设备当前没有可用的 AT 口，因此无法提供 AT 串口终端。'
  }
  return '当前设备暂时无法提供 AT 串口终端，请稍后重试。'
})

watch(
  () => atTemplate.value,
  (v) => {
    const cmd = String(v || '').trim()
    if (cmd) atCmd.value = cmd
  }
)

async function sendAT() {
  const cmd = String(atCmd.value || '').trim()
  if (!cmd) return
  atSending.value = true
  atCmd.value = '' // 清空输入框
  try {
    const result = await devicesService.sendAT(props.deviceId, {
      cmd: cmd,
      timeout_ms: atTimeoutMs.value || 10000
    })
    if (!result.ok) throw new Error(result.error.message || '请求异常')
    atHistory.value.push({
      ts: Date.now(),
      cmd,
      ok: result.data.ok,
      response: result.data.response
    })
  } catch (e: unknown) {
    atHistory.value.push({
      ts: Date.now(),
      cmd,
      ok: false,
      response: e instanceof Error ? e.message : '请求异常'
    })
  } finally {
    atSending.value = false
  }
}

function clearATHistory() {
  atHistory.value = []
}
</script>

<template>
  <div>
    <div class="flex items-center gap-3">
      <div class="w-10 h-10 rounded-xl bg-gray-100 dark:bg-gray-800 flex items-center justify-center text-gray-700 dark:text-gray-300">
        <el-icon size="22"><Code24Regular /></el-icon>
      </div>
      <div>
        <div class="text-lg font-bold text-gray-900 dark:text-white">AT 终端</div>
        <div class="text-sm text-gray-500 dark:text-gray-400 mt-0.5">发送 AT 指令并查看回显（多行响应会完整返回）</div>
      </div>
    </div>

    <template v-if="!canUseATTerminal">
      <div class="mt-4 p-8 flex flex-col items-center justify-center bg-orange-50 dark:bg-orange-900/20 border border-orange-100 dark:border-orange-900/50 rounded-xl">
        <el-icon size="48" class="text-orange-400 mb-4"><Warning24Regular /></el-icon>
        <div class="text-lg font-bold text-orange-700 dark:text-orange-400">{{ unavailableTitle }}</div>
        <div class="text-sm text-orange-600 dark:text-orange-300 mt-2 text-center max-w-md">
          {{ unavailableDescription }}
        </div>
      </div>
    </template>
    <template v-else>
      <!-- 交互历史面板 -->
    <div class="ui-panel-muted mt-4 p-4 h-[320px] overflow-auto flex flex-col gap-3 rounded-xl border border-gray-100 dark:border-white/10 relative">
      <div v-if="atHistory.length === 0 && !atSending" class="absolute inset-0 flex items-center justify-center text-sm text-gray-400">
        暂无 AT 会话记录
      </div>
      <div v-for="(h, i) in atHistory" :key="h.ts + h.cmd + i" class="flex flex-col gap-2 w-full">
        <!-- 请求记录（右侧气泡） -->
        <div class="flex w-full justify-end">
          <div class="max-w-[80%] bg-indigo-500 text-white rounded-2xl rounded-tr-sm px-4 py-2.5 shadow-sm">
            <div class="text-sm font-mono break-words">{{ h.cmd }}</div>
            <div class="text-[10px] text-indigo-100 mt-1 text-right">{{ new Date(h.ts).toLocaleTimeString() }}</div>
          </div>
        </div>

        <!-- 响应/错误记录（左侧气泡） -->
        <div class="flex w-full justify-start">
          <div class="max-w-[80%] rounded-2xl rounded-tl-sm px-4 py-2.5 shadow-sm" :class="!h.ok ? 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-100 dark:border-red-900/50' : 'bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 border border-gray-100 dark:border-white/5'">
            <div class="text-sm whitespace-pre-wrap break-words font-mono">{{ h.response }}</div>
            <div class="text-[10px] mt-1 text-gray-400 flex items-center gap-2">
              <span>{{ new Date(h.ts).toLocaleTimeString() }}</span>
            </div>
          </div>
        </div>

      </div>

      <!-- 发送中等待状态（左侧呼吸气泡） -->
      <div v-if="atSending" class="flex w-full justify-start mt-2">
        <div class="max-w-[80%] bg-white dark:bg-gray-800 rounded-2xl rounded-tl-sm px-4 py-3 shadow-sm border border-gray-100 dark:border-white/5 flex items-center gap-2">
          <div class="flex space-x-1">
            <div class="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:-0.3s]"></div>
            <div class="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce [animation-delay:-0.15s]"></div>
            <div class="w-1.5 h-1.5 bg-indigo-400 rounded-full animate-bounce"></div>
          </div>
          <span class="text-xs text-gray-400 ml-1">等待模组响应...</span>
        </div>
      </div>
    </div>
    <!-- 输入区 -->
    <div class="grid grid-cols-1 md:grid-cols-[200px_1fr_110px_auto] gap-3 mt-4">
      <div class="space-y-1">
        <div class="text-[11px] font-bold text-gray-500 uppercase tracking-wider">快捷指令模板</div>
        <el-select v-model="atTemplate" filterable clearable placeholder="选择常用命令（可选）">
           <el-option-group v-for="g in atTemplates" :key="g.label" :label="g.label">
            <el-option v-for="it in g.items" :key="it.value" :label="it.label" :value="it.value" />
          </el-option-group>
        </el-select>
      </div>

      <div class="space-y-1">
        <div class="text-[11px] font-bold text-gray-500 uppercase tracking-wider">命令</div>
        <el-input
          v-model="atCmd"
          placeholder='例如 AT+CSQ (可自由编辑)'
          @keyup.enter="sendAT"
          :disabled="atSending"
        />
      </div>

      <div class="space-y-1">
        <div class="text-[11px] font-bold text-gray-500 uppercase tracking-wider">超时(ms)</div>
        <el-input v-model.number="atTimeoutMs" type="number" inputmode="numeric" placeholder="10000" />
      </div>

      <div class="space-y-1 self-end">
        <div class="text-[11px] font-bold text-gray-500 uppercase tracking-wider opacity-0 select-none">操作</div>
        <div class="flex items-center justify-end gap-2">
          <el-button type="default" @click="clearATHistory" class="ui-button-plain">清空</el-button>
          <el-button type="primary" :loading="atSending" :disabled="!atCmd" @click="sendAT" class="!border-0">
            发送
          </el-button>
        </div>
      </div>
      </div>
    </template>
  </div>
</template>
