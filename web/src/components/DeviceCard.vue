<script setup lang="ts">
import { computed } from 'vue'
import type { DashboardDevice } from '../types/api'
import StatusLight from './StatusLight.vue'
import {
  Cellular3G24Regular,
  Cellular4G24Regular,
  Cellular5G24Regular,
  CellularData124Regular,
  Wifi124Regular
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
  <!-- Rebuilt for scanning down a grid rather than looking at one tile.
       Removed: the decorative gradient wedge that scaled on hover, the 40px icon
       tile with an inner shadow, and the nested bordered box around the network
       row -- three boxes deep for two facts. Labels now sit in a fixed column so
       values line up vertically across every card, and the status strip runs down
       the left edge so health is readable without reading. -->
  <button
    type="button"
    class="device-card ui-card ui-card-hover"
    :class="device.healthy ? 'is-healthy' : 'is-down'"
    @click="emit('open-device', device.id)"
  >
    <div class="device-card-body">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <h3 class="device-name">{{ device.name || device.id }}</h3>
          <div class="mt-1 flex items-center gap-1.5">
            <StatusLight :tone="device.healthy ? 'success' : 'danger'" size="md" :animated="false" />
            <span
              class="text-[11px] font-medium"
              :class="device.healthy ? 'text-success-600 dark:text-success-400' : 'text-danger-600 dark:text-danger-400'"
            >{{ device.healthy ? '在线' : '离线' }}</span>
          </div>
        </div>

        <div v-if="!device.vowifi_active" class="flex items-center gap-1.5 flex-shrink-0" :title="`${signalLabel} ${device.signal_dbm}dBm`">
          <!-- Meter is aria-hidden: the dBm value beside it carries the same fact. -->
          <div class="flex items-end gap-[2px] h-3" aria-hidden="true">
            <div
              v-for="i in SIGNAL_BAR_COUNT"
              :key="i"
              class="w-[3px] rounded-[1px]"
              :class="bars >= i ? barClass : 'bg-gray-200 dark:bg-white/10'"
              :style="{ height: `${i * 25}%` }"
            />
          </div>
          <span class="text-[11px] tabular-nums text-gray-400">{{ device.signal_dbm }}</span>
        </div>
      </div>

      <dl class="device-facts">
        <dt>网络</dt>
        <dd class="flex items-center gap-1.5 min-w-0">
          <el-icon :class="networkColor" size="15"><component :is="networkIcon" /></el-icon>
          <span class="truncate">{{ device.vowifi_active ? 'Wi-Fi Calling' : (device.operator || '检测中') }}</span>
          <span
            v-if="!device.vowifi_active && networkModeText"
            class="text-[10px] font-medium text-gray-400 tracking-tight"
          >{{ networkModeText }}</span>
        </dd>

        <dt>公网 IP</dt>
        <dd class="tabular-nums truncate">{{ device.public_ip || '—' }}</dd>

        <!-- Names the stage the VoWiFi chain stopped at. Shown only mid-chain: a
             ready or unstarted runtime has nothing to add here. -->
        <template v-if="showVowifiProgress">
          <dt>VoWiFi</dt>
          <dd :class="vowifiProgressClass" class="font-medium truncate">{{ vowifiSummary }}</dd>
        </template>
      </dl>
    </div>
  </button>
</template>

<style scoped>
/* A 2px status strip down the left edge. This is the one piece of colour the card
   uses structurally: scanning a grid, health reads from the edges without the eye
   having to land on each status dot. */
.device-card {
  display: block;
  width: 100%;
  text-align: left;
  padding: 0;
  cursor: pointer;
  position: relative;
  overflow: hidden;
  border-left-width: 2px;
}

.device-card.is-healthy {
  border-left-color: var(--ui-success-edge);
}

.device-card.is-down {
  border-left-color: var(--ui-danger-edge);
}

.device-card:focus-visible {
  outline: 2px solid var(--ui-accent);
  outline-offset: 2px;
}

.device-card-body {
  padding: 0.875rem 1rem 1rem;
}

.device-name {
  font-size: 0.875rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text);
  margin: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Definition list on a fixed label column, so values align vertically across every
   card in the grid. The previous layout used justify-between per row, which put each
   value wherever its own label happened to end. */
.device-facts {
  display: grid;
  grid-template-columns: 4.25rem minmax(0, 1fr);
  align-items: baseline;
  row-gap: 0.3rem;
  column-gap: 0.75rem;
  margin: 0.875rem 0 0;
  padding-top: 0.75rem;
  border-top: 1px solid var(--ui-border-solid);
  font-size: 0.8125rem;
}

.device-facts dt {
  color: var(--ui-text-faint);
  font-size: 0.75rem;
  white-space: nowrap;
}

.device-facts dd {
  margin: 0;
  color: var(--ui-text-muted);
  min-width: 0;
}
</style>
