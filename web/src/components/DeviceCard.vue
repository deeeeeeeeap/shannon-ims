<script setup lang="ts">
import { computed } from 'vue'
import type { DashboardDevice } from '../types/api'
import StatusLight from './StatusLight.vue'
import {
  Cellular3G24Regular,
  Cellular4G24Regular,
  Cellular5G24Regular,
  CellularData124Regular,
  Wifi124Regular,  Globe24Regular,
  Sim24Regular
} from '@vicons/fluent'

import {
  SIGNAL_BAR_COUNT,
  signalBarClass,
  signalBars,
  signalQualityLabel,
} from '../domain/signalQuality'
import { readinessStatus, readinessSummary } from '../domain/vowifiReadiness'

const props = defineProps<{ device: DashboardDevice }>()
const emit = defineEmits<{
  'open-device': [id: string]
}>()

const displayNetworkMode = computed(() => {
  const mode = String(props.device?.network_mode || '').trim()
  const duplex = String(props.device?.network_duplex || '').trim()
  if (!mode) return ''
  return duplex ? `${duplex} ${mode}` : mode
})

const networkIcon = computed(() => {
  // VoWiFi 模式显示 Wi-Fi 图标
  if (props.device?.vowifi_active) return Wifi124Regular
  const mode = displayNetworkMode.value
  if (!mode) return CellularData124Regular
  const m = String(mode).toUpperCase()
  if (m.includes('5G') || m.includes('NR')) return Cellular5G24Regular
  if (m.includes('4G') || m.includes('LTE')) return Cellular4G24Regular
  if (m.includes('3G') || m.includes('WCDMA') || m.includes('HSPA') || m.includes('UMTS')) return Cellular3G24Regular
  return CellularData124Regular
})

// Radio-access-technology colours are a legend, not a quality scale: they let an
// operator pick out "which of these is on Wi-Fi Calling" at a glance across a grid
// of cards. Kept distinct from the semantic ramps for that reason -- a purple 5G
// badge must not read as a warning.
const networkColor = computed(() => {
  if (props.device?.vowifi_active) return 'text-success-600 dark:text-success-400'
  const mode = displayNetworkMode.value
  if (!mode) return 'text-gray-400'
  const m = String(mode).toUpperCase()
  if (m.includes('5G') || m.includes('NR')) return 'text-violet-500 dark:text-violet-400'
  if (m.includes('4G') || m.includes('LTE')) return 'text-primary-500 dark:text-primary-400'
  if (m.includes('3G') || m.includes('WCDMA') || m.includes('HSPA') || m.includes('UMTS')) return 'text-orange-500 dark:text-orange-400'
  return 'text-gray-400'
})

const networkModeText = computed(() => {
  const mode = displayNetworkMode.value
  if (!mode) return ''
  const parts = String(mode).trim().split(/\s+/).filter(Boolean)
  if (parts.length <= 1) return parts[0] || ''
  return parts[1] || ''
})

const hideNetworkModeOnNarrow = computed(() => {
  return networkModeText.value.toUpperCase() === 'LTE'
})

// Signal grading comes from domain/signalQuality so this card and the device
// detail page cannot disagree about the same reading. They used to: this card
// graded green above -70 dBm with 4 bars while the detail page used -85 with 5,
// so a device at -80 showed amber here and green there.
const bars = computed(() => signalBars(props.device?.signal_dbm))
const barClass = computed(() => signalBarClass(props.device?.signal_dbm))
const signalLabel = computed(() => signalQualityLabel(props.device?.signal_dbm))

// VoWiFi is a five-stage chain (SIM -> Access -> Tunnel -> IMS -> SMS). The card
// only had the `vowifi_active` boolean, which cannot say WHERE a half-up runtime
// stopped -- the single most useful fact when a device is not registering.
const vowifiRuntime = computed(() => props.device?.vowifi_runtime)
const vowifiStatus = computed(() => readinessStatus(vowifiRuntime.value))
const vowifiSummary = computed(() => readinessSummary(vowifiRuntime.value))

// Only surfaced when the chain is neither fully ready nor entirely off: a healthy
// runtime needs no explanation and an unstarted one has nothing to report.
const showVowifiProgress = computed(() =>
  vowifiStatus.value === 'progressing' || vowifiStatus.value === 'stalled'
)

const vowifiProgressClass = computed(() => (
  vowifiStatus.value === 'stalled'
    ? 'text-danger-600 dark:text-danger-400'
    : 'text-warning-600 dark:text-warning-400'
))
</script>

<template>
  <button
    type="button"
    class="group relative block w-full overflow-hidden ui-card ui-card-hover text-left transition-all duration-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-gray-950"
    @click="emit('open-device', device.id)"
  >
    <div class="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary-500/10 to-violet-500/10 rounded-bl-full -mr-8 -mt-8 transition-transform group-hover:scale-150" />

    <div class="p-6 relative z-10">
      <div class="flex justify-between items-start mb-6">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-gray-50 dark:bg-white/5 flex items-center justify-center text-primary-600 dark:text-primary-400 shadow-inner">
            <el-icon size="20"><Sim24Regular /></el-icon>
          </div>
          <div>
            <h3 class="font-bold text-base text-gray-800 dark:text-gray-100">{{ device.name || device.id }}</h3>
            <!-- Not animated when healthy. A pulse should mean "changing, look at
                 this", so pulsing every steady-state device turned a grid of cards
                 into constant motion and left nothing for a real transition to
                 stand out against. The mid-chain VoWiFi row below is what pulses
                 now, because that genuinely is in flux. -->
            <div class="flex items-center gap-1.5 mt-0.5">
              <StatusLight :tone="device.healthy ? 'success' : 'danger'" size="md" :animated="false" />
              <span class="text-xs font-medium" :class="device.healthy ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400'">
                {{ device.healthy ? '在线' : '离线' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="space-y-4">
        <div class="flex items-center justify-between p-3 bg-gray-50/50 dark:bg-white/5 rounded-xl border border-gray-100 dark:border-white/5">
          <div class="flex items-center gap-2 min-w-0">
            <div class="flex items-center gap-1.5 opacity-80">
              <el-icon :class="networkColor" size="18">
                <component :is="networkIcon" />
              </el-icon>
              <span
                v-if="!device.vowifi_active && device.network_mode && networkModeText"
                class="text-[11px] font-bold tracking-tighter leading-none"
                :class="hideNetworkModeOnNarrow ? 'hidden xl:inline' : ''"
              >
                {{ networkModeText }}
              </span>
            </div>
            <span class="flex-1 min-w-0 text-sm font-medium text-gray-700 dark:text-gray-300 whitespace-nowrap truncate">
              {{ device.vowifi_active ? 'Wi-Fi Calling' : (device.operator || '检测中...') }}
            </span>
          </div>
          <div
            v-if="!device.vowifi_active"
            class="flex items-center gap-1"
            :title="`${signalLabel} ${device.signal_dbm}dBm`"
          >
            <!-- The meter is decorative; signalLabel above carries the same fact as
                 text, so it is not the only channel. -->
            <div class="flex items-end gap-[2px] h-3" aria-hidden="true">
              <div
                v-for="i in SIGNAL_BAR_COUNT"
                :key="i"
                class="w-1 rounded-sm transition-all duration-500"
                :class="bars >= i ? barClass : 'bg-gray-200 dark:bg-gray-700'"
                :style="{ height: `${i * 25}%` }"
              />
            </div>
            <span class="text-xs font-mono text-gray-400 ml-1 hidden xl:inline">{{ device.signal_dbm }}dBm</span>
          </div>
        </div>

        <div class="space-y-2">
          <div class="flex justify-between items-center text-sm">
            <span class="text-gray-400 flex items-center gap-1.5"><el-icon><Globe24Regular /></el-icon> 公网 IP</span>
            <span class="font-mono font-bold text-primary-600 dark:text-primary-400">{{ device.public_ip || '---' }}</span>
          </div>

          <!-- Names the stage the VoWiFi chain stopped at. The card previously had
               only a vowifi_active boolean, so a runtime stuck at Tunnel and one
               stuck at SMS looked identical here -- and which one it is decides
               where the operator looks next. Shown only while the chain is partly
               up; a ready or unstarted runtime has nothing to add. -->
          <div v-if="showVowifiProgress" class="flex justify-between items-center text-sm">
            <span class="text-gray-400 flex items-center gap-1.5">
              <el-icon><Wifi124Regular /></el-icon> VoWiFi
            </span>
            <span class="text-xs font-semibold" :class="vowifiProgressClass">{{ vowifiSummary }}</span>
          </div>
        </div>
      </div>
    </div>
  </button>
</template>
