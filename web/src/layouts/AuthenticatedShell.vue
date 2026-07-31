<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { Expand, Fold } from '@element-plus/icons-vue'
import LoadingScreen from '../components/LoadingScreen.vue'
import ErrorBoundary from '../components/ErrorBoundary.vue'
import SwitchDark from '../components/SwitchDark.vue'
import SidebarNav, { type SidebarMenuItem } from '../components/SidebarNav.vue'
import { debugCollector } from '../debug/collector'
import {
  Mail24Regular,
  Settings24Regular,
  Board24Regular,
  Phone24Regular,
  Globe24Regular,
  DocumentText24Regular
} from '@vicons/fluent'

defineProps({
  isDark: {
    type: Boolean,
    required: true
  }
})

const emit = defineEmits(['toggle-theme'])

const router = useRouter()
const route = useRoute()
const auth = useAuthStore()
const collapsed = ref(false)
const isMobile = ref(false)
const drawerOpen = ref(false)
const debugOpen = ref(false)
const DebugPanel = defineAsyncComponent(() => import('../components/DebugPanel.vue'))

const menuItems: SidebarMenuItem[] = [
  { index: '/', label: '仪表盘', icon: Board24Regular },
  { index: '/devices', label: '设备管理', icon: Phone24Regular },
  { index: '/proxy', label: '代理管理', icon: Globe24Regular },
  { index: '/sms', label: '短信中心', icon: Mail24Regular },
  { index: '/logs', label: '实时日志', icon: DocumentText24Regular },
  { index: '/settings', label: '系统设置', icon: Settings24Regular }
]

async function handleLogout() {
  const { ElMessageBox } = await import('element-plus')
  const confirmed = await ElMessageBox.confirm('确认退出登录？', '提示', {
    confirmButtonText: '退出',
    cancelButtonText: '取消',
    type: 'warning'
  })
    .then(() => true)
    .catch(() => false)
  if (!confirmed) return
  auth.logout()
  router.push('/login')
}

function syncIsMobile() {
  if (typeof window === 'undefined') return
  isMobile.value = window.matchMedia('(max-width: 767px)').matches
  if (!isMobile.value) {
    drawerOpen.value = false
  }
}

function handleNavToggle() {
  if (isMobile.value) {
    drawerOpen.value = true
  } else {
    collapsed.value = !collapsed.value
  }
}

function onKeydown(e: KeyboardEvent) {
  if (e.ctrlKey && e.shiftKey && String(e.key || '').toLowerCase() === 'd') {
    e.preventDefault()
    debugOpen.value = !debugOpen.value
    localStorage.setItem('debug_panel_open', debugOpen.value ? '1' : '0')
  }
}

onMounted(() => {
  syncIsMobile()
  window.addEventListener('resize', syncIsMobile, { passive: true })

  const saved = localStorage.getItem('debug_panel_open')
  debugOpen.value = saved === '1'

  window.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  window.removeEventListener('resize', syncIsMobile)
  window.removeEventListener('keydown', onKeydown)
})

watch(
  () => route.fullPath,
  () => {
    drawerOpen.value = false
  }
)

watch(
  () => debugOpen.value,
  (v) => {
    localStorage.setItem('debug_panel_open', v ? '1' : '0')
  }
)

watch(
  () => debugCollector.openPanelRequestAt.value,
  (ts) => {
    if (!ts) return
    debugOpen.value = true
  }
)

const activePath = computed(() => route.path)
</script>

<template>
  <el-container v-if="auth.isAuthenticated && route.name !== 'Login'" class="h-full">
    <el-aside
      v-if="!isMobile"
      :width="collapsed ? '52px' : '232px'"
      class="h-full ui-glass transition-[width] duration-200"
    >
      <SidebarNav
        :items="menuItems"
        :active-path="activePath"
        :collapsed="collapsed"
        header-class="h-14"
        @logout="handleLogout"
      />
    </el-aside>

    <el-drawer v-model="drawerOpen" direction="ltr" size="256px" :with-header="false" class="mobile-drawer">
      <div class="h-full bg-white/95 dark:bg-[#141418]/95 backdrop-blur-md">
        <SidebarNav
          :items="menuItems"
          :active-path="activePath"
          header-class="h-16"
          @logout="handleLogout"
        />
      </div>
    </el-drawer>

    <el-container class="h-full">
      <el-header class="h-14 px-4 sm:px-5 flex items-center justify-between ui-glass border-b border-gray-100 dark:border-white/5 sticky top-0 z-10">
        <div class="flex items-center gap-2">
          <!-- Icon-only control: without a label a screen reader announces just
               "button". The label tracks what the click will actually do. -->
          <el-button
            text
            class="!px-2"
            :aria-label="isMobile ? '打开导航菜单' : (collapsed ? '展开侧边栏' : '收起侧边栏')"
            :aria-expanded="isMobile ? drawerOpen : !collapsed"
            @click="handleNavToggle"
          >
            <el-icon>
              <Fold v-if="!isMobile && !collapsed" />
              <Expand v-else />
            </el-icon>
          </el-button>
        </div>

        <div class="flex items-center gap-3">
          <SwitchDark :is-dark="isDark" @toggle="(e) => emit('toggle-theme', e)" />

          <div class="hidden sm:flex items-center justify-center w-7 h-7 rounded-full bg-success-50 dark:bg-success-500/10 border border-success-100 dark:border-success-500/20 shadow-sm">
            <span class="relative flex h-2 w-2">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-success-400 opacity-75"></span>
              <span class="relative inline-flex rounded-full h-2 w-2 bg-success-500"></span>
            </span>
          </div>
        </div>
      </el-header>

      <el-main class="p-4 sm:p-6 overflow-auto bg-gray-50/50 dark:bg-transparent">
        <div class="main-inner mx-auto w-full">
          <router-view v-slot="{ Component, route: r }">
            <ErrorBoundary v-if="Component" title="页面渲染失败">
              <component :is="Component" :key="r.fullPath" />
            </ErrorBoundary>
            <LoadingScreen v-else title="正在加载页面…" subtitle="正在准备页面组件与资源" />
          </router-view>
        </div>
      </el-main>
    </el-container>

    <DebugPanel v-model="debugOpen" />
  </el-container>
</template>

<style scoped>
/* Sidebar styling moved to SidebarNav.vue, which now renders both the desktop
   aside and the mobile drawer. What stays here belongs to the shell frame. */

.main-inner {
  max-width: 100%;
}

/* 240px sidebar + 48px of el-main padding, capped so text lines do not run
   arbitrarily wide on ultrawide displays. */
@media (min-width: 768px) {
  .main-inner {
    max-width: clamp(0px, calc(100vw - 240px - 48px), 80rem);
  }
}

:deep(.mobile-drawer .el-drawer__body) {
  padding: 0 !important;
}
</style>
