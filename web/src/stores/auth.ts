import { defineStore } from 'pinia'
import axios, { type AxiosInstance } from 'axios'
import { debugCollector } from '../debug/collector'
import { noteBackendFailure, noteBackendSuccess } from '../composables/useBackendReachability'

export const api: AxiosInstance = axios.create({
  baseURL: '/api'
})

function isWebsheetRequestURL(raw: unknown) {
  if (typeof raw !== 'string' || raw === '') return false
  try {
    // The base only exists so a relative URL can be parsed for its pathname; it is
    // never fetched. `.invalid` is reserved by RFC 2606 precisely so it cannot
    // resolve. Left un-rebranded on purpose: this is a parser sentinel, not a name
    // anyone sees.
    const path = new URL(raw, 'http://vohive.invalid').pathname
    return /^\/(?:api\/)?websheets(?:\/|$)/.test(path)
  } catch {
    return false
  }
}

api.interceptors.request.use(config => {
  if (isWebsheetRequestURL(config.url)) {
    config.headers.delete('Authorization')
  }
  return config
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
  (response) => {
    noteBackendSuccess()
    return response
  },
  (error) => {
    debugCollector.recordApiError(error)

    // A response with a status means the server answered -- 4xx/5xx are application
    // outcomes, not connectivity failures. Only a request that never got a response
    // (network error, timeout, refused) counts against reachability, otherwise the
    // header indicator would read "down" every time an API legitimately said no.
    if (error?.response) {
      noteBackendSuccess()
    } else {
      noteBackendFailure()
    }

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
