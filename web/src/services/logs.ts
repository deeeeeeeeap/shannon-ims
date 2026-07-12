import { api } from '../stores/auth'
import { callService } from './http'

export type LogEntry = {
  time: string
  level: string
  caller: string
  message: string
  fields?: string
}

export const logsService = {
  history(lines = 500) {
    return callService(async () => {
      const res = await api.get('/logs/history', { params: { lines } })
      return (res.data?.logs || []) as LogEntry[]
    })
  }
}
