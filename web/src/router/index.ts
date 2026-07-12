import { createRouter, createWebHashHistory, type RouteLocationNormalized } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import { debugCollector } from '../debug/collector'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('../views/Login.vue')
    },
    {
      path: '/',
      name: 'Dashboard',
      component: () => import('../views/Dashboard.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/sms',
      name: 'SMS',
      component: () => import('../views/Sms.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/devices',
      name: 'Devices',
      component: () => import('../views/Devices.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/settings',
      name: 'Settings',
      component: () => import('../views/Settings.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/proxy',
      name: 'Proxy',
      component: () => import('../views/Proxy.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/logs',
      name: 'Logs',
      component: () => import('../views/Logs.vue'),
      meta: { requiresAuth: true }
    }
  ]
})

router.beforeEach((to: RouteLocationNormalized) => {
  const authStore = useAuthStore()
  if (to.meta?.requiresAuth && !authStore.isAuthenticated) {
    return '/login'
  }
})

router.afterEach((to, from) => {
  debugCollector.recordRoute(to, from)
})

export default router
