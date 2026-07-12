import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { AppError } from '../types/domain'
import { logsService, type LogEntry } from '../services/logs'

export const useLogsStore = defineStore('logs', () => {
  const logs = ref<LogEntry[]>([])
  const loading = ref(false)
  const lastOkAt = ref<number | null>(null)
  const error = ref<AppError | null>(null)

  function append(entry: LogEntry, max = 1000) {
    logs.value.push(entry)
    if (logs.value.length > max) logs.value = logs.value.slice(-max)
  }

  async function fetchHistory(lines = 500) {
    loading.value = true
    error.value = null
    const result = await logsService.history(lines)
    if (result.ok) {
      logs.value = result.data
      lastOkAt.value = Date.now()
    } else {
      error.value = result.error
    }
    loading.value = false
    return result
  }

  function clear() {
    logs.value = []
  }

  return {
    logs,
    loading,
    lastOkAt,
    error,
    append,
    fetchHistory,
    clear
  }
})
