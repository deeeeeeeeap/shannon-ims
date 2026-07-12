<script setup lang="ts">
import { WeatherMoon24Regular, WeatherSunny24Regular } from '@vicons/fluent'

const props = defineProps<{
  isDark: boolean
}>()

const emit = defineEmits<{
  toggle: [next: boolean]
}>()

function onToggle() {
  emit('toggle', !props.isDark)
}
</script>

<template>
  <el-button circle @click="onToggle" class="!border-0 !bg-gray-100/70 dark:!bg-white/5">
    <el-icon v-if="isDark"><WeatherSunny24Regular /></el-icon>
    <el-icon v-else><WeatherMoon24Regular /></el-icon>
  </el-button>
</template>
