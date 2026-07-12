<script setup lang="ts">
import type { DeviceOverviewItem } from '../types/api'
import { ArrowSync24Regular, Power24Regular, Mail24Regular } from '@vicons/fluent'

defineProps<{
  device: DeviceOverviewItem
  rotating: boolean
  rebooting: boolean
  reconnectingVoWiFi: boolean
}>()

const emit = defineEmits<{
  'copy-text': [value: string]
  'rotate-ip': []
  'reboot-modem': []
  'reconnect-vowifi': []
  'open-sms': []
}>()
</script>

<template>
  <div class="ui-card p-6">
    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
      <div class="min-w-0">
        <div class="flex items-center gap-3">
          <div class="device-header-brand-icon">V</div>
          <div class="min-w-0">
            <div class="text-xl font-extrabold text-gray-900 dark:text-white truncate">{{ device.name || device.id }}</div>
            <div class="text-xs text-gray-500 dark:text-gray-400 mt-0.5 truncate">
              <span class="font-mono cursor-pointer hover:underline" @click="emit('copy-text', device.id)">{{ device.id }}</span>
              · 公网 IP:
              <span class="font-mono cursor-pointer hover:underline" @click="emit('copy-text', device.public_ip || '')">{{ device.public_ip || '---' }}</span>
            </div>
          </div>
        </div>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <el-button v-if="device?.vowifi_enabled" :loading="reconnectingVoWiFi" @click="emit('reconnect-vowifi')" class="ui-glass-border !border-0">
          <el-icon><ArrowSync24Regular /></el-icon>
          重连 VoWiFi
        </el-button>
        <el-button v-else :loading="rotating" :disabled="!device?.network_connected" @click="emit('rotate-ip')" class="ui-glass-border !border-0">
          <el-icon><ArrowSync24Regular /></el-icon>
          切换 IP
        </el-button>
        <el-button :loading="rebooting" @click="emit('reboot-modem')" class="ui-glass-border !border-0 hover:!text-red-600">
          <el-icon><Power24Regular /></el-icon>
          重启模组
        </el-button>
        <el-button @click="emit('open-sms')" class="ui-glass-border !border-0">
          <el-icon><Mail24Regular /></el-icon>
          短信
        </el-button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.device-header-brand-icon {
  width: 2.75rem;
  height: 2.75rem;
  border-radius: 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  background: linear-gradient(135deg, #06b6d4, #14b8a6);
  color: #fff;
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 1.15rem;
  font-weight: 700;
  box-shadow: 0 10px 22px rgba(6, 182, 212, 0.2);
}

</style>
