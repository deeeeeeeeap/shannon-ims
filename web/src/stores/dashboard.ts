import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { DashboardVM } from '../types/view-model'
import type { AppError } from '../types/domain'
import { dashboardService } from '../services/dashboard'
import { createEmptyTrafficAnalysis, trafficService, type TrafficAnalysis, type TrafficRange } from '../services/traffic'

export const useDashboardStore = defineStore('dashboard', () => {
  const devices = ref<DashboardVM[]>([])
  const devicesLoading = ref(false)
  const devicesLastOkAt = ref<number | null>(null)
  const devicesError = ref<AppError | null>(null)

  const analysis = ref<TrafficAnalysis>(createEmptyTrafficAnalysis())
  const analysisLoading = ref(false)
  const analysisLastOkAt = ref<number | null>(null)
  const analysisError = ref<AppError | null>(null)

  async function fetchDevices() {
    devicesLoading.value = true
    devicesError.value = null
    const result = await dashboardService.listDevices()
    if (result.ok) {
      devices.value = result.data
      devicesLastOkAt.value = Date.now()
    } else {
      devicesError.value = result.error
    }
    devicesLoading.value = false
  }

  async function fetchAnalysis(range: TrafficRange) {
    analysisLoading.value = true
    analysisError.value = null
    const result = await trafficService.getAnalysis(range)
    if (result.ok) {
      analysis.value = result.data
      analysisLastOkAt.value = Date.now()
    } else {
      analysis.value = createEmptyTrafficAnalysis()
      analysisError.value = result.error
    }
    analysisLoading.value = false
  }

  return {
    devices,
    devicesLoading,
    devicesLastOkAt,
    devicesError,
    analysis,
    analysisLoading,
    analysisLastOkAt,
    analysisError,
    fetchDevices,
    fetchAnalysis
  }
})
