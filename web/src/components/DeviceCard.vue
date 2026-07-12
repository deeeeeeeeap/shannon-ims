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

const networkColor = computed(() => {
  // VoWiFi 模式显示特殊颜色
  if (props.device?.vowifi_active) return 'text-emerald-500'
  const mode = displayNetworkMode.value
  if (!mode) return 'text-gray-400'
  const m = String(mode).toUpperCase()
  if (m.includes('5G') || m.includes('NR')) return 'text-purple-500'
  if (m.includes('4G') || m.includes('LTE')) return 'text-blue-500'
  if (m.includes('3G')) return 'text-orange-500'
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

function hasValidSignalDbm(dbm: number | null | undefined): dbm is number {
  return typeof dbm === 'number' && Number.isFinite(dbm) && dbm !== 0 && dbm !== -999
}

function getSignalColor(dbm: number | null | undefined) {
  if (!hasValidSignalDbm(dbm)) return 'bg-gray-300 dark:bg-gray-600'
  if (dbm > -70) return 'bg-green-500'
  if (dbm > -90) return 'bg-yellow-500'
  return 'bg-red-500'
}

function getSignalBars(dbm: number | null | undefined) {
  if (!hasValidSignalDbm(dbm)) return 0
  if (dbm > -70) return 4
  if (dbm > -85) return 3
  if (dbm > -100) return 2
  return 1
}
</script>

<template>
  <button
    type="button"
    class="group relative block w-full overflow-hidden ui-card ui-card-hover text-left transition-all duration-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-2 focus-visible:ring-offset-white dark:focus-visible:ring-offset-gray-950"
    @click="emit('open-device', device.id)"
  >
    <div class="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-blue-500/10 to-purple-500/10 rounded-bl-full -mr-8 -mt-8 transition-transform group-hover:scale-150" />

    <div class="p-6 relative z-10">
      <div class="flex justify-between items-start mb-6">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-gray-50 dark:bg-white/5 flex items-center justify-center text-blue-600 dark:text-blue-400 shadow-inner">
            <el-icon size="20"><Sim24Regular /></el-icon>
          </div>
          <div>
            <h3 class="font-bold text-base text-gray-800 dark:text-gray-100">{{ device.name || device.id }}</h3>
            <div class="flex items-center gap-1.5 mt-0.5">
              <StatusLight :tone="device.healthy ? 'success' : 'danger'" size="md" :animated="device.healthy" />
              <span class="text-xs font-medium" :class="device.healthy ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'">
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
          <div v-if="!device.vowifi_active" class="flex items-center gap-1" title="信号强度">
            <div class="flex items-end gap-[2px] h-3">
              <div
                v-for="i in 4"
                :key="i"
                class="w-1 rounded-sm transition-all duration-500"
                :class="getSignalBars(device.signal_dbm) >= i ? getSignalColor(device.signal_dbm) : 'bg-gray-200 dark:bg-gray-700'"
                :style="{ height: `${i * 25}%` }"
              />
            </div>
            <span class="text-xs font-mono text-gray-400 ml-1 hidden xl:inline">{{ device.signal_dbm }}dBm</span>
          </div>
        </div>

        <div class="space-y-2">
          <div class="flex justify-between items-center text-sm">
            <span class="text-gray-400 flex items-center gap-1.5"><el-icon><Globe24Regular /></el-icon> 公网 IP</span>
            <span class="font-mono font-bold text-blue-600 dark:text-blue-400">{{ device.public_ip || '---' }}</span>
          </div>
        </div>
      </div>
    </div>
  </button>
</template>
