import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type { AppError } from '../types/domain'
import type { ProxyDevice, ProxyInstance, ProxyInstanceStatus } from '../types/api'
import { proxyService } from '../services/proxy'

export const useProxyStore = defineStore('proxy', () => {
  const instances = ref<ProxyInstance[]>([])
  const devices = ref<ProxyDevice[]>([])
  const statuses = ref<ProxyInstanceStatus[]>([])

  const loading = ref(false)
  const lastOkAt = ref<number | null>(null)
  const error = ref<AppError | null>(null)

  const statusMap = computed<Record<string, ProxyInstanceStatus>>(() => {
    return Object.fromEntries(statuses.value.map((s) => [s.id, s]))
  })

  async function fetchOverview() {
    loading.value = true
    error.value = null
    const result = await proxyService.overview()
    if (result.ok) {
      instances.value = result.data.instances || []
      devices.value = result.data.devices || []
      statuses.value = result.data.status || []
      lastOkAt.value = Date.now()
    } else {
      error.value = result.error
    }
    loading.value = false
    return result
  }

  async function fetchInstance(id: string) {
    return proxyService.getInstance(id)
  }

  async function saveConfig(nextInstances: ProxyInstance[]) {
    return proxyService.saveConfig(nextInstances)
  }

  async function startInstance(id: string) {
    return proxyService.startInstance(id)
  }

  async function stopInstance(id: string) {
    return proxyService.stopInstance(id)
  }

  async function restartInstance(id: string) {
    return proxyService.restartInstance(id)
  }

  return {
    instances,
    devices,
    statuses,
    statusMap,
    loading,
    lastOkAt,
    error,
    fetchOverview,
    fetchInstance,
    saveConfig,
    startInstance,
    stopInstance,
    restartInstance
  }
})
