<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '../stores/auth'
import { useRoute, useRouter } from 'vue-router'
import { Person24Regular, LockClosed24Regular, ArrowRight24Regular } from '@vicons/fluent'

const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

const form = ref({
  username: '',
  password: ''
})

const loading = ref(false)

async function handleLogin() {
  const { ElMessage } = await import('element-plus')
  if (!form.value.username || !form.value.password) {
    ElMessage.warning('请输入用户名和密码')
    return
  }
  loading.value = true
  // Mock delay for feel
  await new Promise<void>(r => setTimeout(r, 600))
  const success = await auth.login(form.value.username, form.value.password)
  loading.value = false

  if (success) {
    ElMessage.success('欢迎回来')
    const q = typeof route.query.redirect === 'string' ? route.query.redirect : ''
    let redirect = q ? decodeURIComponent(q) : ''
    if (!redirect) {
      try {
        redirect = sessionStorage.getItem('post_login_redirect') || ''
      } catch {
        // Ignore sessionStorage read failures.
      }
    }
    if (redirect) {
      try {
        sessionStorage.removeItem('post_login_redirect')
      } catch {
        // Ignore sessionStorage delete failures.
      }
      router.push(redirect)
    } else {
      router.push('/')
    }
  } else {
    ElMessage.error('登录失败，请检查凭证')
  }
}
</script>

<template>
  <div class="relative w-full h-full flex items-center justify-center overflow-hidden">
    <div class="absolute -top-32 -left-32 w-[520px] h-[520px] rounded-full bg-indigo-500/15 dark:bg-indigo-500/20 blur-[120px] animate-pulse-slow" />
    <div class="absolute -bottom-32 -right-32 w-[520px] h-[520px] rounded-full bg-purple-500/15 dark:bg-purple-500/20 blur-[120px] animate-pulse-slow" style="animation-delay: 2s" />

    <div class="relative w-full max-w-md p-1">
      <div class="relative bg-white/70 dark:bg-[#141418]/70 backdrop-blur-xl border border-gray-100 dark:border-white/10 rounded-2xl p-8 shadow-2xl overflow-hidden group">
        <div class="absolute inset-0 bg-gradient-to-br from-indigo-500/8 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />

        <div class="text-center mb-10 relative z-10">
          <div class="w-20 h-20 bg-gradient-to-tr from-indigo-500 to-purple-600 rounded-2xl mx-auto flex items-center justify-center text-white text-2xl font-bold shadow-lg shadow-indigo-500/20 mb-6 transform group-hover:scale-105 transition-transform duration-300">
            VH
          </div>
          <h2 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-gray-900 to-gray-600 dark:from-white dark:to-gray-400">
            VoHive
          </h2>
          <p class="text-gray-500 dark:text-gray-400 text-sm mt-3 tracking-wide">4G 模组管理后台</p>
        </div>

        <form @submit.prevent="handleLogin" class="space-y-6 relative z-10">
          <div class="space-y-2">
            <div class="relative">
              <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-400 dark:text-gray-500">
                <Person24Regular class="w-5 h-5" />
              </div>
              <input                v-model="form.username"                class="w-full bg-white/70 dark:bg-black/20 border border-gray-200 dark:border-white/10 rounded-lg py-3 pl-10 pr-4 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/25 focus:border-indigo-500/40 transition-all font-mono text-sm"
                placeholder="用户名"
                type="text"
              />
            </div>
          </div>

          <div class="space-y-2">
            <div class="relative">
              <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-400 dark:text-gray-500">
                <LockClosed24Regular class="w-5 h-5" />
              </div>
              <input                v-model="form.password"                class="w-full bg-white/70 dark:bg-black/20 border border-gray-200 dark:border-white/10 rounded-lg py-3 pl-10 pr-4 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/25 focus:border-indigo-500/40 transition-all font-mono text-sm"
                placeholder="密码"
                type="password"
              />
            </div>
          </div>

          <button            type="submit"            :disabled="loading"
            class="w-full bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-bold py-3 px-4 rounded-lg shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2 transform active:scale-95 transition-all duration-200 disabled:opacity-70 disabled:cursor-not-allowed"
          >
            <span v-if="loading" class="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
            <span v-else>登录</span>
            <ArrowRight24Regular v-if="!loading" class="w-5 h-5" />
          </button>
        </form>
      </div>
      <div class="text-center mt-6">
        <p class="text-gray-500 text-xs">VoHive &copy; 2026</p>
      </div>
    </div>
  </div>
</template>
