<script setup lang="ts">
import { WeatherMoon24Regular, WeatherSunny24Regular } from '@vicons/fluent'

// A plain <button>, not <el-button circle>.
//
// This component sits in BOTH shells, including the unauthenticated one, and it was
// the only Element Plus consumer on the login path -- Login.vue and LoadingScreen
// use none. Those two tags (el-button + el-icon) therefore pulled the whole 757 KB
// element-plus chunk into the login page for a 32px icon button.
//
// The metrics below match `.el-button.is-circle` exactly (32x32, border-radius 50%,
// padding 8px, 1em icon), so the control is visually identical in both shells; the
// callers pass no Element Plus props, so nothing else was being used.
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
  <button
    type="button"
    class="switch-dark"
    :aria-label="isDark ? '切换到亮色主题' : '切换到暗色主题'"
    :aria-pressed="isDark"
    @click="onToggle"
  >
    <!-- aria-hidden: the accessible name is on the button, so the glyph would
         otherwise be announced twice. -->
    <component :is="isDark ? WeatherSunny24Regular : WeatherMoon24Regular" aria-hidden="true" />
  </button>
</template>

<style scoped>
.switch-dark {
  width: 32px;
  height: 32px;
  padding: 8px;
  border: 0;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  color: var(--el-text-color-regular, #606266);
  background: rgba(243, 244, 246, 0.7);
  transition: background-color 160ms ease, color 160ms ease, box-shadow 160ms ease;
  box-shadow: var(--ui-btn-shadow);
}

.switch-dark:hover {
  color: var(--ui-accent);
  box-shadow: var(--ui-btn-shadow-hover);
}

/* Keyboard focus must stay visible; the ring uses the accent token so it tracks
   the theme rather than hardcoding a colour. */
.switch-dark:focus-visible {
  outline: 2px solid var(--ui-accent);
  outline-offset: 2px;
}

.switch-dark:active {
  transform: translateY(0.5px);
}

.switch-dark svg {
  width: 1em;
  height: 1em;
  display: block;
}

:global(html.dark) .switch-dark {
  color: rgba(255, 255, 255, 0.72);
  background: rgba(255, 255, 255, 0.05);
}

@media (prefers-reduced-motion: reduce) {
  .switch-dark {
    transition: none;
  }

  .switch-dark:active {
    transform: none;
  }
}
</style>
