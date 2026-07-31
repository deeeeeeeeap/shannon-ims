<script setup lang="ts">
import { computed } from 'vue'
import type { DeviceOverviewItem } from '../types/api'
import {
  ArrowSync24Regular,
  Power24Regular,
  Mail24Regular,
  Wifi124Regular,
  CellularData124Regular
} from '@vicons/fluent'
import { isControlOnline, isRecoveryPhase } from '../utils/deviceLifecycle'

const props = defineProps<{
  device: DeviceOverviewItem
  rotating: boolean
  rebooting: boolean
  reconnectingVoWiFi: boolean
}>()

// The tile used to show a hardcoded "V" -- the old brand initial -- on a teal
// gradient with a coloured drop shadow. It said nothing about the device it sat
// next to, and it was the last place still using the pre-rebrand palette.
//
// It now carries the one fact worth glancing at: which bearer this device is on,
// tinted by whether the control plane is actually up.
const onWifiCalling = computed(() => !!props.device?.vowifi_active)
const bearerIcon = computed(() => (onWifiCalling.value ? Wifi124Regular : CellularData124Regular))

const health = computed<'ok' | 'transitional' | 'down'>(() => {
  if (isRecoveryPhase(props.device?.lifecycle_phase)) return 'transitional'
  return isControlOnline(props.device) ? 'ok' : 'down'
})

const bearerLabel = computed(() => {
  const bearer = onWifiCalling.value ? 'Wi-Fi Calling' : '蜂窝数据'
  const state = health.value === 'ok' ? '控制面在线' : health.value === 'transitional' ? '恢复中' : '控制面离线'
  return `${bearer}，${state}`
})

const emit = defineEmits<{
  'copy-text': [value: string]
  'rotate-ip': []
  'reboot-modem': []
  'reconnect-vowifi': []
  'open-sms': []
}>()
</script>

<template>
  <div class="ui-card px-5 py-4">
    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
      <div class="min-w-0">
        <div class="flex items-center gap-3">
          <span class="device-bearer" :class="`is-${health}`" :title="bearerLabel" :aria-label="bearerLabel">
            <component :is="bearerIcon" aria-hidden="true" />
          </span>
          <div class="min-w-0">
            <div class="device-title truncate">{{ device.name || device.id }}</div>
            <div class="device-meta truncate">
              <button type="button" class="device-meta-copy" @click="emit('copy-text', device.id)">{{ device.id }}</button>
              <span class="device-meta-sep">·</span>
              <span class="device-meta-label">公网 IP</span>
              <button type="button" class="device-meta-copy" @click="emit('copy-text', device.public_ip || '')">{{ device.public_ip || '—' }}</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Plain bordered buttons. The glass variant with !border-0 left these
           floating with no edge, so a row of destructive and non-destructive
           actions read as one undifferentiated strip. -->
      <div class="flex flex-wrap items-center gap-2">
        <el-button v-if="device?.vowifi_enabled" size="small" :loading="reconnectingVoWiFi" @click="emit('reconnect-vowifi')">
          <el-icon><ArrowSync24Regular /></el-icon>
          重连 VoWiFi
        </el-button>
        <el-button v-else size="small" :loading="rotating" :disabled="!device?.network_connected" @click="emit('rotate-ip')">
          <el-icon><ArrowSync24Regular /></el-icon>
          切换 IP
        </el-button>
        <el-button size="small" @click="emit('open-sms')">
          <el-icon><Mail24Regular /></el-icon>
          短信
        </el-button>
        <!-- Rebooting the modem drops the tunnel and the registration, so it is
             marked as destructive rather than sitting inline with the others. -->
        <el-button size="small" type="danger" plain :loading="rebooting" @click="emit('reboot-modem')">
          <el-icon><Power24Regular /></el-icon>
          重启模组
        </el-button>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 32px, tinted background, no gradient and no coloured shadow. The tint carries
   control-plane health so the icon is doing two jobs at once: bearer type from its
   shape, health from its colour. */
.device-bearer {
  width: 2rem;
  height: 2rem;
  border-radius: var(--ui-radius-sm);
  display: grid;
  place-items: center;
  flex-shrink: 0;
}

.device-bearer :deep(svg) {
  width: 1.05rem;
  height: 1.05rem;
}

.device-bearer.is-ok {
  background: var(--ui-accent-soft);
  color: var(--ui-accent-strong);
}

.device-bearer.is-transitional {
  background: rgba(245, 158, 11, 0.12);
  color: #b45309;
}

.device-bearer.is-down {
  background: rgba(239, 68, 68, 0.1);
  color: #b91c1c;
}

:global(html.dark) .device-bearer.is-transitional {
  color: #fcd34d;
}

:global(html.dark) .device-bearer.is-down {
  color: #fca5a5;
}

/* 15px, not 20px extrabold. The device name is a label on this panel, not the
   page title -- PageHeader above it already holds that role, and two competing
   headings is what made the detail view feel top-heavy. */
.device-title {
  font-size: 0.9375rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--ui-text);
}

.device-meta {
  margin-top: 0.125rem;
  font-size: 0.75rem;
  color: var(--ui-text-faint);
  display: flex;
  align-items: baseline;
  gap: 0.375rem;
  min-width: 0;
}

.device-meta-sep {
  opacity: 0.6;
}

.device-meta-label {
  color: var(--ui-text-faint);
}

/* These were <span>s with a click handler and a hover underline -- looked like
   links, unreachable by keyboard. Real buttons, since clicking copies. */
.device-meta-copy {
  border: 0;
  padding: 0;
  background: none;
  font: inherit;
  font-variant-numeric: tabular-nums;
  color: var(--ui-text-muted);
  cursor: pointer;
}

.device-meta-copy:hover {
  color: var(--ui-accent-strong);
  text-decoration: underline;
}

.device-meta-copy:focus-visible {
  outline: 2px solid var(--ui-accent);
  outline-offset: 2px;
  border-radius: 2px;
}
</style>
