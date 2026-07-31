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
  // No artificial delay here. There used to be a 600ms sleep labelled "mock delay
  // for feel", which only made signing in slower.
  const success = await auth.login(form.value.username, form.value.password)
  loading.value = false

  if (success) {
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
  <!-- Deliberately plain.
       This screen used to carry two 520px pulsing blur orbs, a gradient-filled
       wordmark, a gradient logo tile that scaled on hover, and a gradient submit
       button with shadow-2xl. None of it told the operator anything, and the
       combination is what reads as generic. What is left is a single framed panel,
       one accent (the submit button), and type doing the hierarchy. -->
  <div class="w-full h-full flex items-center justify-center px-6">
    <div class="w-full max-w-sm">
      <div class="login-panel">
        <div class="mb-8">
          <div class="flex items-baseline gap-2">
            <h1 class="text-xl font-semibold tracking-tight text-gray-900 dark:text-gray-50">Shannon</h1>
            <span class="text-xl font-light tracking-tight text-gray-400 dark:text-gray-500">IMS</span>
          </div>
          <p class="mt-1.5 text-[13px] text-gray-500 dark:text-gray-400">VoWiFi 设备管理控制台</p>
        </div>

        <form class="space-y-3" @submit.prevent="handleLogin">
          <label class="login-field">
            <span class="login-field-icon"><Person24Regular /></span>
            <input
              v-model="form.username"
              type="text"
              autocomplete="username"
              placeholder="用户名"
              aria-label="用户名"
            />
          </label>

          <label class="login-field">
            <span class="login-field-icon"><LockClosed24Regular /></span>
            <input
              v-model="form.password"
              type="password"
              autocomplete="current-password"
              placeholder="密码"
              aria-label="密码"
            />
          </label>

          <button type="submit" class="login-submit" :disabled="loading">
            <span v-if="loading" class="login-spinner" aria-hidden="true" />
            <span>{{ loading ? '登录中' : '登录' }}</span>
            <ArrowRight24Regular v-if="!loading" class="login-submit-arrow" aria-hidden="true" />
          </button>
        </form>
      </div>

      <p class="mt-5 text-center text-[11px] text-gray-400 dark:text-gray-500 tabular-nums">
        Shannon IMS &middot; 2026
      </p>
    </div>
  </div>
</template>

<style scoped>
/* One border, one radius step, no blur. The panel reads as a single surface
   rather than a card floating over decoration. */
.login-panel {
  background: var(--ui-surface-solid);
  border: 1px solid var(--ui-border-solid);
  border-radius: var(--ui-radius-lg);
  padding: 2rem;
  box-shadow: var(--ui-shadow-sm);
}

.login-field {
  display: flex;
  align-items: center;
  gap: 0.625rem;
  height: 2.75rem;
  padding: 0 0.875rem;
  border: 1px solid var(--ui-border-solid);
  border-radius: var(--ui-radius-sm);
  background: var(--ui-surface-solid-muted);
  transition: border-color 140ms ease, box-shadow 140ms ease;
}

/* focus-within, not focus: the ring belongs to the whole field so the icon is
   inside it. */
.login-field:focus-within {
  border-color: var(--ui-accent);
  box-shadow: 0 0 0 3px var(--ui-accent-soft);
}

.login-field-icon {
  display: flex;
  flex-shrink: 0;
  color: var(--ui-text-faint);
}

.login-field-icon :deep(svg) {
  width: 1.05rem;
  height: 1.05rem;
}

.login-field input {
  flex: 1;
  min-width: 0;
  border: 0;
  outline: 0;
  background: transparent;
  font-size: 0.875rem;
  color: inherit;
}

.login-field input::placeholder {
  color: var(--ui-text-faint);
}

.login-submit {
  width: 100%;
  height: 2.75rem;
  margin-top: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  border: 0;
  border-radius: var(--ui-radius-sm);
  background: var(--ui-accent);
  color: #fff;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 140ms ease;
}

.login-submit:hover:not(:disabled) {
  background: var(--ui-accent-strong);
}

.login-submit:focus-visible {
  outline: 2px solid var(--ui-accent);
  outline-offset: 2px;
}

.login-submit:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.login-submit-arrow {
  width: 1rem;
  height: 1rem;
}

.login-spinner {
  width: 0.875rem;
  height: 0.875rem;
  border: 2px solid rgba(255, 255, 255, 0.35);
  border-top-color: #fff;
  border-radius: 50%;
  animation: login-spin 600ms linear infinite;
}

@keyframes login-spin {
  to { transform: rotate(360deg); }
}

@media (prefers-reduced-motion: reduce) {
  .login-spinner {
    animation-duration: 2s;
  }
}
</style>
