import type {
  DashboardDevice,
  DeviceMgmtListItem,
  DeviceOverviewItem,
  ProxyInstance,
  ProxyOverviewResponse,
  SMSContact,
  SMSMessage
} from './api'

export type SmsThreadVM = {
  key: string
  imsi: string
  peer: string
  deviceId?: string
  lastTs: number
  lastSmsId: number
  lastMessage: string
  lastDeviceName?: string
  localPhone?: string
  peerLower: string
  lastMessageLower: string
}

export type DashboardVM = DashboardDevice
export type DeviceListVM = DeviceMgmtListItem
export type DeviceDetailVM = DeviceOverviewItem
export type ProxyOverviewVM = ProxyOverviewResponse
export type ProxyInstanceVM = ProxyInstance
export type SMSContactDTO = SMSContact
export type SMSMessageDTO = SMSMessage
