import type { DeviceLifecyclePhase, DeviceMgmtListItem, DeviceOverviewItem } from '../types/api'

type DeviceLike = Pick<
  DeviceMgmtListItem | DeviceOverviewItem,
  'running' | 'healthy' | 'control_online' | 'lifecycle_phase' | 'modem'
>

export function isRecoveryPhase(phase?: DeviceLifecyclePhase) {
  return phase === 'rebooting' ||
    phase === 'usb_wait' ||
    phase === 'worker_starting' ||
    phase === 'qmi_starting' ||
    phase === 'recovering' ||
    phase === 'evicting'
}

export function isControlOnline(device: DeviceLike | null | undefined) {
  if (!device) return false
  if (isRecoveryPhase(device.lifecycle_phase)) return false
  return !!device.running && (device.control_online ?? device.healthy) === true
}

export function isRadioRegistered(device: DeviceLike | null | undefined) {
  const r = device?.modem?.reg_status
  return r === 1 || r === 5
}

export function lifecycleStatusLabel(phase?: DeviceLifecyclePhase) {
  switch (phase) {
    case 'rebooting':
      return '重启中'
    case 'usb_wait':
      return '等待设备重新枚举'
    case 'worker_starting':
      return '设备启动中'
    case 'qmi_starting':
      return 'QMI 启动中'
    case 'recovering':
      return '控制面恢复中'
    case 'degraded':
      return '控制面不稳定'
    case 'evicting':
      return '重新接管中'
    case 'online':
      return '在线'
    case 'offline':
      return '离线'
    default:
      return ''
  }
}

export function primaryLifecycleStatus(device: DeviceLike | null | undefined) {
  const phase = device?.lifecycle_phase
  if (isRecoveryPhase(phase)) {
    return { label: lifecycleStatusLabel(phase) || '恢复中', tag: 'warning' as const, tone: 'warning' as const, animated: true }
  }
  if (phase === 'degraded') {
    return { label: '不稳定', tag: 'warning' as const, tone: 'warning' as const, animated: true }
  }
  if (!device?.running) {
    return { label: '离线', tag: 'danger' as const, tone: 'danger' as const, animated: false }
  }
  if (!isControlOnline(device)) {
    return { label: '恢复中', tag: 'warning' as const, tone: 'warning' as const, animated: true }
  }
  return { label: '在线', tag: 'success' as const, tone: 'success' as const, animated: true }
}
