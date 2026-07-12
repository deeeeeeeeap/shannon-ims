import { defineStore } from 'pinia'
import axios, { type AxiosInstance } from 'axios'
import { debugCollector } from '../debug/collector'

export const api: AxiosInstance = axios.create({
  baseURL: '/api'
})

try {
  const token = localStorage.getItem('token') || ''
  if (token) {
    api.defaults.headers.common.Authorization = `Bearer ${token}`
  }
} catch {
  // localStorage may be unavailable in some sandboxed contexts.
}

type AuthState = {
  token: string
  user: unknown | null
}

export const useAuthStore = defineStore('auth', {
  state: (): AuthState => ({
    token: localStorage.getItem('token') || '',
    user: null
  }),
  getters: {
    isAuthenticated: (state: AuthState) => !!state.token
  },
  actions: {
    async login(username: string, password: string) {
      try {
        const res = await api.post<{ token?: string }>('/auth/login', { username, password })
        const token = String(res.data?.token || '')
        this.token = token
        localStorage.setItem('token', token)
        api.defaults.headers.common.Authorization = `Bearer ${token}`
        return true
      } catch (e) {
        console.error(e)
        return false
      }
    },
    logout() {
      this.token = ''
      localStorage.removeItem('token')
      delete api.defaults.headers.common.Authorization
    }
  }
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    debugCollector.recordApiError(error)
    if (error?.response?.status === 401) {
      try {
        const current = String(window.location.hash || '').replace(/^#/, '') || '/'
        if (!current.startsWith('/login')) {
          sessionStorage.setItem('post_login_redirect', current)
          debugCollector.recordAuthEvent({ ts: Date.now(), kind: '401_redirect', redirectTo: current })
          window.location.hash = `#/login?redirect=${encodeURIComponent(current)}`
          const auth = useAuthStore()
          auth.logout()
          return Promise.reject(error)
        }
      } catch {
        // Accessing sessionStorage/window hash can fail in restricted contexts.
      }
      const auth = useAuthStore()
      auth.logout()
      window.location.hash = '#/login'
    }
    return Promise.reject(error)
  }
)
