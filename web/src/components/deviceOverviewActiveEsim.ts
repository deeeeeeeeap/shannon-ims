import type { DeviceOverviewItem } from '../types/api'

export function activeEsimProfileDisplayName(device: Pick<DeviceOverviewItem, 'active_esim_profile_name'> | null | undefined) {
  return device?.active_esim_profile_name?.trim() || ''
}
