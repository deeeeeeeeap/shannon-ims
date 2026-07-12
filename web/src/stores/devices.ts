import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { AppError } from '../types/domain'
import type { DeviceConfigDTO, DiscoveredDevice, OperatorScanResult } from '../types/api'
import type { DeviceDetailVM, DeviceListVM } from '../types/view-model'
import { devicesService } from '../services/devices'
import { useEventStream } from '../composables/useEventStream'

export const useDevicesStore = defineStore('devices', () => {
  const list = ref<DeviceListVM[]>([])
  const deviceLimit = ref<number>(0)
  const detail = ref<DeviceDetailVM | null>(null)
  const discovered = ref<DiscoveredDevice[]>([])
  const config = ref<DeviceConfigDTO | null>(null)

  const loading = ref(false)
  const lastOkAt = ref<number | null>(null)
  const error = ref<AppError | null>(null)
  const operatorScans = ref<Record<string, OperatorScanResult | null>>({})

  const operatorScanStreams: Record<string, ReturnType<typeof useEventStream<OperatorScanResult>> | null> = {}

  function getOperatorScan(deviceId: string) {
    return operatorScans.value[deviceId] ?? null
  }

  function getOrCreateOperatorScanStream(deviceId: string) {
    let stream = operatorScanStreams[deviceId]
    if (stream) return stream

    stream = useEventStream<OperatorScanResult>({
      path: `/devices/${deviceId}/operator_selection/scan/stream`,
      eventName: 'operator_scan',
      reconnectDelayMs: 2000,
      parse: (payload: string) => JSON.parse(payload) as OperatorScanResult,
      onEvent: (data: OperatorScanResult) => {
        operatorScans.value = {
          ...operatorScans.value,
          [deviceId]: data
        }
        if (data.status !== 'running') {
          operatorScanStreams[deviceId]?.setPaused(true)
        }
      }
    })
    operatorScanStreams[deviceId] = stream
    return stream
  }

  async function startOperatorScan(deviceId: string) {
    const stream = getOrCreateOperatorScanStream(deviceId)
    stream.setPaused(false)
  }

  async function resumeOperatorScan(deviceId: string) {
    const current = getOperatorScan(deviceId)
    if (current?.status === 'running') {
      const stream = getOrCreateOperatorScanStream(deviceId)
      stream.setPaused(false)
    }
  }

  function clearOperatorScan(deviceId: string) {
    operatorScanStreams[deviceId]?.setPaused(true)
    operatorScanStreams[deviceId]?.disconnect()
    operatorScanStreams[deviceId] = null
    operatorScans.value = {
      ...operatorScans.value,
      [deviceId]: null
    }
  }

  async function fetchList(signal?: AbortSignal) {
    const result = await devicesService.listManaged(signal)
    if (result.ok) {
      list.value = result.data.devices
      deviceLimit.value = result.data.deviceLimit
      lastOkAt.value = Date.now()
      error.value = null
    } else {
      error.value = result.error
    }
    return result
  }

  async function fetchDetail(id: string, signal?: AbortSignal) {
    const result = await devicesService.getOverviewLite(id, signal)
    if (result.ok) detail.value = result.data
    return result
  }

  async function fetchConfig(id: string) {
    const result = await devicesService.getConfig(id)
    if (result.ok) config.value = result.data
    return result
  }

  async function fetchDiscovered() {
    const result = await devicesService.listDiscovered()
    if (result.ok) discovered.value = Array.isArray(result.data) ? result.data : []
    return result
  }

  return {
    list,
    deviceLimit,
    detail,
    discovered,
    config,
    loading,
    lastOkAt,
    error,
    operatorScans,
    fetchList,
    fetchDetail,
    fetchConfig,
    fetchDiscovered,
    getOperatorScan,
    startOperatorScan,
    resumeOperatorScan,
    clearOperatorScan
  }
})
