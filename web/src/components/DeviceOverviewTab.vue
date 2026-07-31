<script setup lang="ts">
import { ref, computed } from 'vue'
import { Eye24Regular, EyeOff24Regular } from '@vicons/fluent'
import type { DeviceOverviewItem } from '../types/api'
import { useSensitiveVisibility } from '../composables/useSensitiveVisibility'
import { activeEsimProfileDisplayName } from './deviceOverviewActiveEsim'
import { isControlOnline, isRadioRegistered, isRecoveryPhase, lifecycleStatusLabel } from '../utils/deviceLifecycle'
import StatusLight from './StatusLight.vue'
import OperatorSelectionDialog from './OperatorSelectionDialog.vue'
import { Settings24Regular } from '@vicons/fluent'
import type { StatusLightTone } from './statusLight'
import {
  SIGNAL_BAR_COUNT,
  hasValidSignalDbm,
  signalBarClass,
  signalBars,
  signalQualityLabel,
  signalToneClass,
} from '../domain/signalQuality'
import {
  hasRuntimeFault,
  readinessStages,
  readinessStatus,
  readinessSummary,
} from '../domain/vowifiReadiness'

const props = defineProps<{
  device: DeviceOverviewItem | null
  simOperatorDisplay: string
  trafficSpeedRx: string
  trafficSpeedTx: string
  trafficMinuteRx: string
  trafficMinuteTx: string
  e911Starting: boolean
}>()

const emit = defineEmits<{
  'setup-e911': []
  'refresh': []
}>()

const showSensitive = useSensitiveVisibility()
const showOperatorSelection = ref(false)

const trafficStateLabel = computed(() => {
  const status = props.device?.traffic_meta?.status
  if (status === 'waiting_sample') return '等待采样'
  if (status === 'stale') return '采样中断'
  return ''
})

function trafficDisplay(value: string | undefined) {
  return trafficStateLabel.value || value
}

const trafficRxDisplay = computed(() => props.trafficMinuteRx || trafficDisplay(props.device?.traffic?.rx))
const trafficTxDisplay = computed(() => props.trafficMinuteTx || trafficDisplay(props.device?.traffic?.tx))
const trafficDownloadRateDisplay = computed(() => props.trafficSpeedRx || trafficDisplay(props.device?.traffic?.rate) || '--')
const trafficUploadRateDisplay = computed(() => props.trafficSpeedTx || trafficStateLabel.value || '--')

// 次要字段折叠状态（VoWiFi 模式）
const showVowifiDetail = ref(false)

// ---- VoWiFi 模式计算属性 ----

// Readiness comes from domain/vowifiReadiness so the chain order and the
// stalled/progressing distinction are defined in exactly one place.
//
// The local version graded with some()/every(), which collapsed "stopped at
// Tunnel" and "stopped at SMS" into the same "partial" -- and those need different
// operator responses. It also listed unready stages unordered, so the chain's
// direction was invisible.
const readinessItems = computed(() => readinessStages(props.device?.vowifi_runtime))

// 'ready' | 'progressing' | 'stalled' | 'off'
const vowifiStatus = computed(() => readinessStatus(props.device?.vowifi_runtime))

// Names the stage to act on, e.g. "受阻于 隧道就绪（2/5）".
const vowifiSummary = computed(() => readinessSummary(props.device?.vowifi_runtime))

// Auto-expands the detail block when the runtime reported a fault.
const hasError = computed(() => hasRuntimeFault(props.device?.vowifi_runtime))

// A partly-up chain is mid-transition; ready and off are both steady states.
const vowifiInFlux = computed(() =>
  vowifiStatus.value === 'progressing' || vowifiStatus.value === 'stalled'
)

// ---- 窝蜂模式计算属性 ----

// Signal grading comes from domain/signalQuality. The rating and the colours are
// shared with DeviceCard: the two used to grade independently (-85 here vs -70
// there), so one device could read green on its detail page and amber on the
// dashboard at the same instant.
//
// The meter still draws SIGNAL_BAR_COUNT bars, and the count is imported rather
// than written as a literal so the template cannot drift from the domain module.
const signalDbm = computed(() => props.device?.modem?.signal_dbm)
const signalLevel = computed(() => signalBars(signalDbm.value))
const signalColorClass = computed(() => signalToneClass(signalDbm.value))
const signalBarColor = computed(() => signalBarClass(signalDbm.value))
const signalLabel = computed(() => signalQualityLabel(signalDbm.value))
const signalHasReading = computed(() => hasValidSignalDbm(signalDbm.value))

const flightModeEnabled = computed(() => {
  if (props.device?.vowifi_active) return true
  const mode = props.device?.modem?.operating_mode
  return mode === 0 || mode === 4
})

// `stalled` is danger rather than warning: the chain is half up AND the runtime
// reported a fault, so waiting will not fix it. `progressing` stays warning
// because it may still complete on its own.
const vowifiStatusTone = computed<StatusLightTone>(() => {
  switch (vowifiStatus.value) {
    case 'ready':
      return 'success'
    case 'progressing':
      return 'warning'
    case 'stalled':
      return 'danger'
    case 'off':
    default:
      return 'neutral'
  }
})

const flightModeStatusText = computed(() => {
  return flightModeEnabled.value ? '是' : '否'
})

const activeEsimProfileName = computed(() => activeEsimProfileDisplayName(props.device))

const controlOnline = computed(() => isControlOnline(props.device))

const isRegistered = computed(() => isRadioRegistered(props.device))

const cellularStatusTone = computed<StatusLightTone>(() => {
  if (isRecoveryPhase(props.device?.lifecycle_phase)) return 'warning'
  if (!controlOnline.value) return 'danger'
  return isRegistered.value ? 'success' : 'warning'
})

// Pulses while the radio is still working towards a registration -- recovering, or
// online but not yet registered. Successful registration is a steady state and used
// to be the one thing that pulsed, which is backwards.
const cellularInFlux = computed(() =>
  isRecoveryPhase(props.device?.lifecycle_phase) ||
  (controlOnline.value && !isRegistered.value)
)

const cellularStatusText = computed(() => {
  const phaseText = lifecycleStatusLabel(props.device?.lifecycle_phase)
  if (phaseText && props.device?.lifecycle_phase !== 'online' && props.device?.lifecycle_phase !== 'offline') return phaseText
  if (!controlOnline.value) return props.device?.running ? '控制面恢复中' : '离线'
  if (isRegistered.value) return ''
  if (props.device?.registration_state_label === 'searching') return '搜索网络中'
  if (props.device?.registration_state_label === 'denied') return '驻网被拒'
  return '未驻网'
})

const networkPanelMessage = computed(() => {
  if (!props.device?.network_enabled) return '数据未开启'
  if (!props.device?.network_connected) return '数据网络未连接'
  return ''
})

</script>

<template>
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">

    <!-- ===== 运行状态面板 ===== -->
    <div class="ui-panel-muted p-4">
      <div class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">运行状态</div>

      <!-- ── VoWiFi 模式 ── -->
      <template v-if="device?.vowifi_enabled">

        <!-- Hero pill -->
        <!-- Four states, not three. `stalled` (half up + runtime fault) now reads
             as danger instead of sharing amber with `progressing`, because waiting
             will not clear it. `off` is neutral rather than red: never started is
             not the same as broken. -->
        <div
          class="flex items-center gap-2.5 rounded-xl px-3.5 py-2.5 mb-3 border"
          :class="{
            'bg-success-50 border-success-200 dark:bg-success-500/10 dark:border-success-500/25': vowifiStatus === 'ready',
            'bg-warning-50 border-warning-200 dark:bg-warning-500/10 dark:border-warning-500/25': vowifiStatus === 'progressing',
            'bg-danger-50 border-danger-200 dark:bg-danger-500/10 dark:border-danger-500/25': vowifiStatus === 'stalled',
            'bg-gray-50 border-gray-200 dark:bg-white/5 dark:border-white/10': vowifiStatus === 'off',
          }"
        >
          <!-- Pulses only mid-transition: a settled chain, ready or off, should not
               compete for attention. -->
          <StatusLight :tone="vowifiStatusTone" size="sm" :animated="vowifiInFlux" />
          <div class="min-w-0">
            <div class="text-sm font-bold leading-tight" :class="{
              'text-success-700 dark:text-success-300': vowifiStatus === 'ready',
              'text-warning-700 dark:text-warning-300': vowifiStatus === 'progressing',
              'text-danger-700 dark:text-danger-300': vowifiStatus === 'stalled',
              'text-gray-600 dark:text-gray-300': vowifiStatus === 'off',
            }">
              <template v-if="vowifiStatus === 'ready'">WiFi-Calling · 全部就绪</template>
              <!-- Names the blocking stage. The old text listed every unready stage
                   unordered ("IMS · SMS 未就绪"), which hid the fact that IMS is
                   what SMS is waiting on. -->
              <template v-else-if="vowifiInFlux">{{ vowifiSummary }}</template>
              <template v-else>VoWiFi 未连接</template>
            </div>
            <div v-if="vowifiInFlux && device?.vowifi_runtime?.last_reason"
              class="text-xs mt-0.5 truncate"
              :class="vowifiStatus === 'stalled' ? 'text-danger-600 dark:text-danger-400' : 'text-warning-600 dark:text-warning-400'">
              {{ device.vowifi_runtime.last_reason }}
            </div>
          </div>
        </div>

        <!-- Readiness chain: SIM -> Access -> Tunnel -> IMS -> SMS, left to right.
             The order is the information. Previously every unready segment was
             painted the same red, which implied five independent failures; in fact
             only the FIRST one is a failure and the rest are simply blocked behind
             it. So the blocking stage is marked and the ones after it are left
             muted. -->
        <div class="mb-3" role="group" :aria-label="`VoWiFi 就绪链：${vowifiSummary}`">
          <div class="flex gap-1 mb-1">
            <div
              v-for="item in readinessItems" :key="item.key"
              class="flex-1 h-1.5 rounded-full transition-colors"
              :class="item.ready ? 'bg-success-500 dark:bg-success-400'
                    : item.blocking ? (vowifiStatus === 'stalled' ? 'bg-danger-500 dark:bg-danger-400' : 'bg-warning-500 dark:bg-warning-400')
                    : 'bg-gray-200 dark:bg-white/10'"
            />
          </div>
          <div class="flex justify-between">
            <span
              v-for="item in readinessItems" :key="item.key"
              class="flex-1 text-center text-[10px]"
              :class="item.blocking ? (vowifiStatus === 'stalled' ? 'text-danger-600 dark:text-danger-400 font-bold' : 'text-warning-600 dark:text-warning-400 font-bold')
                    : item.ready ? 'text-gray-500 dark:text-gray-400'
                    : 'text-gray-400 dark:text-gray-600'"
              :title="`${item.label}${item.ready ? '：已就绪' : item.blocking ? '：当前受阻' : '：等待前序环节'}`"
            >{{ item.key }}</span>
          </div>
        </div>

        <!-- 次要字段（有错误自动展开，否则可折叠） -->
        <div class="border border-gray-200 dark:border-white/10 rounded-lg overflow-hidden">
          <button
            class="w-full flex items-center justify-between px-3 py-2 text-xs text-gray-500 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-white/5 transition-colors"
            @click="showVowifiDetail = !showVowifiDetail"
          >
            <span class="font-bold uppercase tracking-wider">详情</span>
            <span>{{ showVowifiDetail || hasError ? '▴' : '▾' }}</span>
          </button>
          <div v-if="showVowifiDetail || hasError" class="px-3 pb-2 space-y-1.5 text-sm text-gray-700 dark:text-gray-200 border-t border-gray-100 dark:border-white/5 pt-2">
            <FieldRow label="数据平面" :value="device?.vowifi_runtime?.dataplane_mode || '--'" monospace />
            <FieldRow label="最后原因" :value="device?.vowifi_runtime?.last_reason || '--'" />
            <FieldRow label="错误分类" :value="device?.vowifi_runtime?.last_error_class || '--'" monospace copyable />
          </div>
        </div>
      </template>

      <!-- ── 窝蜂模式 ── -->
      <template v-else>

        <!-- 运营商 hero（与 VoWiFi pill 统一样式） -->
        <div class="flex items-center gap-2.5 rounded-xl px-3.5 py-2.5 mb-3 border"
          :class="isRegistered
            ? 'bg-success-50 border-success-200 dark:bg-success-500/10 dark:border-success-500/25'
            : controlOnline
              ? 'bg-warning-50 border-warning-200 dark:bg-warning-500/10 dark:border-warning-500/25'
              : 'bg-gray-100 border-gray-200 dark:bg-white/5 dark:border-white/10'"
        >
          <StatusLight :tone="cellularStatusTone" size="sm" :animated="cellularInFlux" />
          <div class="flex-1 min-w-0">
            <div class="text-sm font-bold leading-tight"
              :class="isRegistered
                ? 'text-success-700 dark:text-success-300'
                : controlOnline
                  ? 'text-warning-700 dark:text-warning-300'
                  : 'text-gray-500 dark:text-gray-400'"
            >
              <template v-if="isRegistered">
                {{ device?.modem?.operator || '--' }}
                <span v-if="device?.modem?.network_mode" class="opacity-70">· {{ [device?.modem?.network_duplex, device?.modem?.network_mode].filter(Boolean).join(' ') }}</span>
              </template>
              <template v-else>
                {{ cellularStatusText }}
              </template>
            </div>
          </div>
          <button @click="showOperatorSelection = true" class="p-1 rounded hover:bg-black/5 dark:hover:bg-white/10 transition-colors" title="网络选择设置">
            <Settings24Regular class="w-5 h-5 text-gray-500 dark:text-gray-400" />
          </button>
        </div>

        <!-- 信号大字 -->
        <div class="rounded-xl border border-gray-200 dark:border-white/10 px-3.5 py-3 mb-3">
          <div class="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-1.5">信号强度</div>
          <div class="flex items-center gap-3">
            <div>
              <div class="flex items-baseline gap-1.5">
                <span class="text-2xl font-extrabold tabular-nums leading-none" :class="signalColorClass">
                  {{ signalHasReading ? signalDbm : '--' }}
                </span>
                <span class="text-xs text-gray-400">dBm</span>
                <!-- -80 dBm means nothing without a scale. The word rating is also
                     the accessible text for the bar meter, which is aria-hidden. -->
                <span class="text-[11px] font-semibold" :class="signalColorClass">{{ signalLabel }}</span>
              </div>
              <div class="text-[10px] text-gray-400 mt-1">
                RSRP {{ device?.modem?.signal_rsrp ?? '--' }}
                &nbsp;·&nbsp;
                RSRQ {{ device?.modem?.signal_rsrq ?? '--' }}
                &nbsp;·&nbsp;
                SINR {{ device?.modem?.signal_sinr ?? '--' }}
                <template v-if="device?.modem?.nr5g_signal_sinr !== undefined">
                  &nbsp;·&nbsp;NR5G SINR {{ device?.modem?.nr5g_signal_sinr }}
                </template>
              </div>
            </div>
            <!-- Bar count comes from the domain module, not a literal: it used to
                 be a hardcoded 5 against a 5-level scale, and now that grading is
                 shared with DeviceCard a literal here would silently leave the last
                 bar permanently dark. The meter is aria-hidden because signalLabel
                 states the same rating in words. -->
            <div
              class="flex items-end gap-0.5 ml-auto"
              style="height: 28px"
              :title="signalHasReading ? signalLabel : '无信号读数'"
              aria-hidden="true"
            >
              <div v-for="i in SIGNAL_BAR_COUNT" :key="i"
                class="w-1.5 rounded-sm"
                :style="{ height: (i * 22 + 12) + '%' }"
                :class="i <= signalLevel ? signalBarColor : 'bg-gray-200 dark:bg-white/10'"
              />
            </div>
          </div>
        </div>

        <!-- 次要字段 -->
        <div class="space-y-1.5 text-sm text-gray-700 dark:text-gray-200">
          <FieldRow label="网络模式"  :value="[device?.modem?.network_duplex, device?.modem?.network_mode].filter(Boolean).join(' ') || '--'" monospace />
          <FieldRow label="频段"  :value="device?.modem?.radio_band || '--'" monospace />
          <FieldRow label="信道"  :value="device?.modem?.radio_channel ? String(device.modem.radio_channel) : '--'" monospace />
          <FieldRow label="注册状态"  :value="device?.modem?.reg_status_text || '--'" monospace />
        </div>
      </template>
    </div>

    <!-- ===== SIM / 设备面板（不变）===== -->
    <div class="ui-panel-muted p-4 relative min-w-0 overflow-hidden">
      <div class="flex items-center justify-between mb-2">
        <div class="text-xs font-bold text-gray-500 uppercase tracking-wider">SIM / 设备</div>
        <div class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 cursor-pointer -mt-1 -mr-1" @click="showSensitive = !showSensitive">
          <el-icon size="18">
            <Eye24Regular v-if="showSensitive" />
            <EyeOff24Regular v-else />
          </el-icon>
        </div>
      </div>
      <div class="text-sm space-y-1.5 text-gray-700 dark:text-gray-200">
        <FieldRow label="IMEI"      :value="device?.modem?.imei"   :sensitive="!showSensitive" monospace copyable />
        <FieldRow label="ICCID"     :value="device?.modem?.iccid"  :sensitive="!showSensitive" monospace copyable />
        <FieldRow label="IMSI"      :value="device?.modem?.imsi"   :sensitive="!showSensitive" monospace copyable />
        <FieldRow label="本机号码" :value="device?.local_phone || '--'"  :sensitive="!showSensitive" monospace copyable />
        <div v-if="device?.e911_setup_available" class="flex justify-between gap-3">
          <span class="text-gray-500">E911地址</span>
          <el-button
            size="small"
            type="primary"
            plain
            :loading="e911Starting"
            class="!border-0"
            @click="emit('setup-e911')"
          >
            设置
          </el-button>
        </div>
        <FieldRow v-if="activeEsimProfileName" label="当前eSIM" :value="activeEsimProfileName" monospace copyable />
        <FieldRow label="原运营商" :value="simOperatorDisplay" copyable />
        <FieldRow label="固件版本"      :value="device?.modem?.firmware" monospace copyable />
        <div class="flex justify-between gap-3">
          <span class="text-gray-500">飞行模式</span>
          <span>{{ flightModeStatusText }}</span>
        </div>
        <FieldRow label="运行模式"  :value="device?.backend_mode === 'qmi' ? 'QMI' : device?.backend_mode === 'mbim' ? 'MBIM' : device?.backend_mode === 'at' ? 'AT' : 'Auto'" monospace />
      </div>
    </div>

    <!-- ===== 流量面板（不变）===== -->
    <div class="ui-panel-muted p-4">
      <div class="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">网络</div>
      <div v-if="networkPanelMessage" class="flex items-center justify-center p-6 text-sm text-gray-400">
        {{ networkPanelMessage }}
      </div>
      <div v-else class="text-sm space-y-1.5 text-gray-700 dark:text-gray-200">
        <FieldRow label="内网 IPv4"     :value="device?.private_ip"           monospace copyable />
        <FieldRow label="内网 IPv6"   :value="device?.private_ipv6"         monospace copyable />
        <FieldRow label="外网 IPv4"     :value="device?.public_ip"            monospace copyable />
        <FieldRow label="外网 IPv6"   :value="device?.public_ipv6"          monospace copyable />
        <FieldRow label="近1分钟上传" :value="trafficTxDisplay"             monospace />
        <FieldRow label="近1分钟下载" :value="trafficRxDisplay"             monospace />
        <FieldRow label="实时下载速率"    :value="trafficDownloadRateDisplay"   monospace />
        <FieldRow label="实时上传速率"    :value="trafficUploadRateDisplay"     monospace />
      </div>
    </div>

    <!-- 运营商选择弹窗 -->
    <OperatorSelectionDialog
      v-if="device?.id"
      v-model="showOperatorSelection"
      :device-id="device.id"
      @updated="emit('refresh')"
    />
  </div>
</template>
