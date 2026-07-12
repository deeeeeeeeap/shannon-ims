import type { EsimSpaceDelta } from '../types/api'

export type OperationNotice = {
  tone: 'success' | 'warning' | 'error'
  message: string
}

function formatApproxBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return ''
  if (bytes >= 1024 * 1024) {
    return `${Math.round((bytes / (1024 * 1024)) * 100) / 100} MB`
  }
  if (bytes >= 1024) {
    return `${Math.round(bytes / 1024)} KB`
  }
  return `${Math.round(bytes)} B`
}

export function describeSpaceDelta(spaceDelta?: Partial<EsimSpaceDelta>): string {
  if (!spaceDelta) return ''
  const formatted = formatApproxBytes(spaceDelta.bytes ?? 0)
  if (!formatted) return ''
  if (spaceDelta.direction === 'released') {
    return `刚刚释放约 ${formatted}`
  }
  if (spaceDelta.direction === 'consumed') {
    return `刚刚占用约 ${formatted}`
  }
  return ''
}

export function describeDeleteResultNotice(result: { warning?: string; space_delta?: Partial<EsimSpaceDelta> }): OperationNotice {
  if (result.warning) {
    return {
      tone: 'warning',
      message: result.warning
    }
  }
  const delta = describeSpaceDelta(result.space_delta)
  return {
    tone: 'success',
    message: delta ? `Profile 删除成功，${delta}` : 'Profile 删除成功'
  }
}

export function describeDownloadTerminalNotice(event: { step: string; msg: string; pct: number; warning?: string; space_delta?: Partial<EsimSpaceDelta> }): OperationNotice {
  if (event.step === 'error') {
    return {
      tone: 'error',
      message: event.msg
    }
  }
  if (event.warning) {
    return {
      tone: 'warning',
      message: event.warning
    }
  }
  const delta = describeSpaceDelta(event.space_delta)
  return {
    tone: 'success',
    message: delta ? `Profile 下载成功，${delta}` : 'Profile 下载成功'
  }
}
