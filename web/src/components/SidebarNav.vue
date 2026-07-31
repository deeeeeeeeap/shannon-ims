<script setup lang="ts">
import { Settings24Regular, SignOut24Regular } from '@vicons/fluent'
import type { Component } from 'vue'

// One implementation of the sidebar, used by BOTH the desktop `el-aside` and the
// mobile `el-drawer` in AuthenticatedShell.
//
// The two used to be separate copies of the same markup -- brand block, menu loop
// and user card written out twice -- so every nav change had to be made in two
// places and the drawer had already drifted (it kept a taller header and had no
// collapsed state to account for). The only real difference is that the drawer is
// never collapsed, which is now just `collapsed = false`.

export type SidebarMenuItem = {
  index: string
  label: string
  icon: Component
}

withDefaults(defineProps<{
  items: SidebarMenuItem[]
  activePath: string
  collapsed?: boolean
  /** Header height differs between the fixed aside (h-14) and the drawer (h-16). */
  headerClass?: string
}>(), {
  collapsed: false,
  headerClass: 'h-14',
})

defineEmits<{ (e: 'logout'): void }>()
</script>

<template>
  <div class="h-full relative sidebar-shell">
    <!-- The wordmark carries the brand, not a gradient tile. The mark shown when
         collapsed is a plain monogram in the accent colour; at full width the name
         is set in two weights instead of being filled with a gradient. -->
    <div class="px-4 flex items-center" :class="[headerClass, collapsed ? 'justify-center px-0' : '']">
      <div v-if="collapsed" class="sidebar-monogram">S</div>
      <div v-else class="sidebar-wordmark">
        <span class="sidebar-wordmark-name">Shannon</span>
        <span class="sidebar-wordmark-suffix">IMS</span>
      </div>
    </div>

    <el-menu
      :collapse="collapsed"
      :collapse-transition="false"
      :default-active="activePath"
      class="sidebar-menu !border-0 !border-r-0 !bg-transparent mt-2"
      router
    >
      <el-menu-item v-for="item in items" :key="item.index" :index="item.index">
        <el-icon><component :is="item.icon" /></el-icon>
        <template #title><span class="sidebar-menu-label">{{ item.label }}</span></template>
      </el-menu-item>
    </el-menu>

    <div v-if="!collapsed" class="absolute bottom-4 w-full px-3">
      <div class="ui-panel-muted p-3 flex items-center gap-3">
        <div class="w-9 h-9 rounded-xl bg-primary-50 dark:bg-primary-500/10 flex items-center justify-center text-primary-600 dark:text-primary-300">
          <el-icon><Settings24Regular /></el-icon>
        </div>
        <div class="flex-1 min-w-0">
          <div class="text-sm font-bold truncate">Admin</div>
          <div class="text-xs text-gray-400 truncate">Administrator</div>
        </div>
        <el-button text type="danger" aria-label="退出登录" @click="$emit('logout')">
          <el-icon><SignOut24Regular /></el-icon>
        </el-button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.sidebar-shell {
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
  --sidebar-menu-text: #475569;
  --sidebar-menu-hover-bg: var(--ui-accent-soft);
  --sidebar-menu-active-bg: var(--ui-accent-soft);
  --sidebar-menu-active-color: var(--ui-accent-strong);
  --sidebar-menu-active-ring: var(--ui-accent-ring);
}

/* Two weights of one typeface, no gradient fill and no drop shadow. The previous
   version painted the name with a linear-gradient through background-clip:text and
   sat it next to a gradient tile with a coloured glow -- a lot of effect for a
   six-letter word, and the single loudest "generic dashboard" cue in the shell. */
.sidebar-wordmark {
  display: flex;
  align-items: baseline;
  gap: 0.3rem;
  white-space: nowrap;
  min-width: 0;
}

.sidebar-wordmark-name {
  font-size: 0.98rem;
  font-weight: 600;
  letter-spacing: -0.015em;
  color: var(--ui-text);
}

.sidebar-wordmark-suffix {
  font-size: 0.98rem;
  font-weight: 300;
  letter-spacing: 0.02em;
  color: var(--ui-text-faint);
}

.sidebar-monogram {
  width: 1.5rem;
  height: 1.5rem;
  border-radius: var(--ui-radius-sm);
  display: grid;
  place-items: center;
  flex-shrink: 0;
  background: var(--ui-accent-soft);
  color: var(--ui-accent-strong);
  font-size: 0.78rem;
  font-weight: 600;
}

.sidebar-menu-label {
  font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-weight: 500;
  letter-spacing: -0.01em;
}

/* Only the text colour needs a dark override: the accent variables are already
   redefined for html.dark in style.css, so hover/active/ring follow along. */
:global(html.dark) .sidebar-shell {
  --sidebar-menu-text: rgba(255, 255, 255, 0.72);
}

/* el-menu ships fixed item heights, a right border and a 3px active bar, none of
   which fit a rounded pill nav. Element Plus exposes the colours as CSS variables
   (used here) but not the geometry, so the metrics below still need :deep(). */
:deep(.sidebar-menu) {
  border-right: 0 !important;
  --el-menu-hover-bg-color: var(--sidebar-menu-hover-bg);
  --el-menu-active-color: var(--sidebar-menu-active-color);
  --el-menu-text-color: var(--sidebar-menu-text);
}

:deep(.sidebar-menu .el-menu-item) {
  height: 40px;
  min-height: 40px;
  line-height: 40px;
  margin: 2px 8px;
  border-radius: 10px;
  padding-left: 13px !important;
  padding-right: 13px !important;
  font-size: 0.94rem;
  font-weight: 400;
  letter-spacing: 0;
  color: var(--sidebar-menu-text);
  transition: background-color 160ms ease, color 160ms ease, box-shadow 160ms ease;
}

:deep(.sidebar-menu .el-menu-item .el-icon) {
  margin-right: 8px !important;
  font-size: 1.18rem;
}

:deep(.sidebar-menu .el-menu-item .el-icon svg) {
  width: 1.18rem;
  height: 1.18rem;
}

:deep(.sidebar-menu .el-menu-item:hover) {
  background: var(--sidebar-menu-hover-bg);
}

:deep(.sidebar-menu .el-menu-item.is-active) {
  background: var(--sidebar-menu-active-bg);
  color: var(--sidebar-menu-active-color);
  box-shadow: inset 0 0 0 1px var(--sidebar-menu-active-ring);
}

:deep(.sidebar-menu .el-menu-item.is-active .el-icon),
:deep(.sidebar-menu .el-menu-item.is-active .sidebar-menu-label) {
  color: inherit;
}

/* The default active indicator is a bar on the right edge; the pill background
   above replaces it. */
:deep(.sidebar-menu .el-menu-item::after) {
  display: none !important;
}

/* Collapsed rail: el-menu wraps each item in a tooltip trigger that assumes a
   full-width row, so the icon needs re-centring inside a square target. */
:deep(.sidebar-menu.el-menu--collapse) {
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
}

:deep(.sidebar-menu.el-menu--collapse .el-menu-item) {
  width: 36px;
  height: 36px;
  min-height: 36px;
  line-height: 36px;
  margin: 3px auto;
  border-radius: 10px;
  display: grid;
  place-items: center;
  padding: 0 !important;
}

:deep(.sidebar-menu.el-menu--collapse .el-menu-item .el-icon) {
  width: 1.18rem;
  height: 1.18rem;
  margin: 0 !important;
  font-size: 1.18rem;
  line-height: 1;
  display: grid;
  place-items: center;
}

:deep(.sidebar-menu.el-menu--collapse .el-menu-item .el-icon svg) {
  width: 1.18rem;
  height: 1.18rem;
  display: block;
}

:deep(.sidebar-menu.el-menu--collapse .el-menu-item .el-menu-tooltip__trigger) {
  position: static;
  inset: auto;
  width: 100%;
  height: 100%;
  padding: 0 !important;
  display: grid;
  place-items: center;
}

:deep(.sidebar-menu.el-menu--collapse > .el-menu-item [class^=el-icon]) {
  width: 1.18rem !important;
}

:deep(.sidebar-menu.el-menu--collapse .el-tooltip) {
  width: 36px;
  display: grid;
  place-items: center;
}

:deep(.sidebar-menu.el-menu--collapse .el-tooltip__trigger) {
  width: 36px;
  height: 36px;
  display: grid;
  place-items: center;
}
</style>
