import test from 'node:test'
import assert from 'node:assert/strict'
import { AxiosError } from 'axios'
import { createPinia, setActivePinia } from 'pinia'

const memory = new Map<string, string>()
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: {
    getItem: (key: string) => memory.get(key) ?? null,
    setItem: (key: string, value: string) => { memory.set(key, value) },
    removeItem: (key: string) => { memory.delete(key) }
  }
})

const { api, useAuthStore } = await import('../src/stores/auth')

test('failed login does not log the request containing credentials', async t => {
  setActivePinia(createPinia())
  const output: unknown[][] = []
  t.mock.method(console, 'error', (...args: unknown[]) => { output.push(args) })
  const oldAdapter = api.defaults.adapter
  t.after(() => { api.defaults.adapter = oldAdapter })
  api.defaults.adapter = async config => {
    throw new AxiosError('Synthetic network failure', 'ERR_NETWORK', config)
  }

  const auth = useAuthStore()
  assert.equal(await auth.login('synthetic-user', 'synthetic-form-value'), false)
  assert.equal(auth.isAuthenticated, false)
  assert.equal(output.length, 0, 'Axios errors can contain the complete login body')
})

test('successful login still creates the client session', async t => {
  setActivePinia(createPinia())
  const oldAdapter = api.defaults.adapter
  t.after(() => { api.defaults.adapter = oldAdapter; useAuthStore().logout() })
  api.defaults.adapter = async config => ({
    data: { token: 'synthetic-session' }, status: 200, statusText: 'OK', headers: {}, config
  })
  const auth = useAuthStore()
  assert.equal(await auth.login('synthetic-user', 'synthetic-form-value'), true)
  assert.equal(auth.isAuthenticated, true)
  assert.equal(memory.has('token'), true)
})
