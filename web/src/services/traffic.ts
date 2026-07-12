import { api } from '../stores/auth'
import { callService } from './http'

export type TrafficRange = 'day' | 'week' | 'month'
export type TrafficBucket = { bucket: string; rx_bytes: number; tx_bytes: number; total_bytes: number }
export type TrafficChart = { timestamps: string[]; devices: string[]; series: Record<string, number[]> }
export type TrafficAnalysis = { buckets: TrafficBucket[]; chart: TrafficChart | null }

export function createEmptyTrafficAnalysis(): TrafficAnalysis {
  return { buckets: [], chart: null }
}

export const trafficService = {
  getAnalysis(range: TrafficRange, deviceId?: string, signal?: AbortSignal) {
    return callService(async () => {
      const params: Record<string, string> = { range }
      if (typeof deviceId === 'string' && deviceId.trim()) {
        params.device_id = deviceId.trim()
      }
      const res = await api.get('/traffic/analysis', { params, signal })
      return {
        buckets: (res?.data?.buckets || []) as TrafficBucket[],
        chart: (res?.data?.chart || null) as TrafficChart | null
      } as TrafficAnalysis
    })
  }
}
