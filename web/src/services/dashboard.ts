import { api } from '../stores/auth'
import { callService } from './http'
import type { DashboardVM } from '../types/view-model'

export const dashboardService = {
  listDevices() {
    return callService(async () => {
      const res = await api.get('/dashboard/devices')
      return (res.data || []) as DashboardVM[]
    })
  }
}
