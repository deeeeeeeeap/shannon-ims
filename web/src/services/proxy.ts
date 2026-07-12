import { api } from '../stores/auth'
import { callService } from './http'
import type { ProxyInstance, ProxyOverviewResponse } from '../types/api'

export const proxyService = {
  overview() {
    return callService(async () => {
      const res = await api.get('/proxy-instances/overview')
      return res.data as ProxyOverviewResponse
    })
  },
  getInstance(id: string) {
    return callService(async () => {
      const res = await api.get(`/proxy-instances/${id}`)
      return res.data as ProxyInstance
    })
  },
  saveConfig(instances: ProxyInstance[]) {
    return callService(async () => {
      await api.put('/proxy-instances/config', { instances })
      return true
    })
  },
  startInstance(id: string) {
    return callService(async () => {
      await api.post(`/proxy-instances/${id}/actions/start`)
      return true
    })
  },
  stopInstance(id: string) {
    return callService(async () => {
      await api.post(`/proxy-instances/${id}/actions/stop`)
      return true
    })
  },
  restartInstance(id: string) {
    return callService(async () => {
      await api.post(`/proxy-instances/${id}/actions/restart`)
      return true
    })
  }
}
