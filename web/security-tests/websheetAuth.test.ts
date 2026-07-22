import test from 'node:test'
import assert from 'node:assert/strict'

const memory = new Map<string, string>()
const storage = {
  getItem(key: string) {
    return memory.get(key) ?? null
  },
  setItem(key: string, value: string) {
    memory.set(key, value)
  },
  removeItem(key: string) {
    memory.delete(key)
  }
}

Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage })
Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: storage })
Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: {
    location: {
      hash: '',
      origin: 'http://127.0.0.1'
    }
  }
})

const { api } = await import('../src/stores/auth')

function authorizationHeader(headers: unknown) {
  const value = headers as {
    get?: (name: string) => unknown
    Authorization?: unknown
  }
  return typeof value?.get === 'function'
    ? value.get('Authorization')
    : value?.Authorization
}

test('Websheet requests never carry the management Authorization header', async () => {
  api.defaults.headers.common.Authorization = 'Bearer synthetic-management-value'
  let carriedAuthorization = false

  await api.get('/websheets/synthetic-session', {
    adapter: async config => {
      carriedAuthorization = authorizationHeader(config.headers) != null
      return { data: null, status: 204, statusText: 'No Content', headers: {}, config }
    }
  })

  assert.ok(!carriedAuthorization, 'Websheet request carried an Authorization header')
})
