import axios from 'axios'
import type { AppError, ServiceResult } from '../types/domain'
import { fail, ok } from '../types/domain'

export function toAppError(err: unknown): AppError {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status
    const data = err.response?.data as unknown
    let message = err.message || 'Request failed'
    if (typeof data === 'string') {
      message = data || message
    } else if (data && typeof data === 'object') {
      const obj = data as Record<string, unknown>
      if (typeof obj.message === 'string' && obj.message) {
        message = obj.message
      } else if (typeof obj.error === 'string' && obj.error) {
        message = obj.error
      }
      const code = typeof obj.code === 'string' ? obj.code : undefined
      return {
        message,
        status,
        method: err.config?.method,
        url: err.config?.url,
        code: code || err.code
      }
    }
    return {
      message,
      status,
      method: err.config?.method,
      url: err.config?.url,
      code: err.code
    }
  }
  if (err instanceof Error) return { message: err.message }
  return { message: String(err) }
}

export async function callService<T>(fn: () => Promise<T>): Promise<ServiceResult<T>> {
  try {
    return ok(await fn())
  } catch (err) {
    return fail(toAppError(err))
  }
}

// `result.error` from callService() is a plain AppError object, never a native
// Error instance, so `e instanceof Error` in catch blocks is always false and
// silently discards the real backend message in favor of a generic fallback.
export function errorMessage(e: unknown, fallback: string): string {
  if (e instanceof Error) return e.message
  if (e && typeof e === 'object' && typeof (e as { message?: unknown }).message === 'string') {
    return (e as { message: string }).message
  }
  return fallback
}
