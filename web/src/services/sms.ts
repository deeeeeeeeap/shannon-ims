import axios from 'axios'
import { api } from '../stores/auth'
import { callService, toAppError } from './http'
import type { ServiceResult } from '../types/domain'
import { fail, ok } from '../types/domain'
import type { DeviceMgmtListItem } from '../types/api'
import type { SMSContactDTO, SMSMessageDTO, SmsThreadVM } from '../types/view-model'

export type SmsThreadQueryParams = {
  peer: string
  limit: number
  device_id?: string
  imsi?: string
  before_ts?: string
  before_id?: number
}

export type SmsSendPayload = {
  device_id?: string
  imsi?: string
  phone: string
  message: string
}

export type SmsSendResult = {
  partsTotal: number
  messageId: string
  deliveryState: string
  message: string
}

export type SmsDeliveryResult = {
  state: string
  acks: number
  partsTotal: number
  failedPartCause?: number
}

export type SmsDeleteThreadPayload = {
  device_id?: string
  imsi?: string
  peer: string
}

type SmsSendAPIResponse = {
  parts_total?: number
  message_id?: string
  delivery_state?: string
  message?: string
}

function normalizeSmsSendResponse(data?: SmsSendAPIResponse): SmsSendResult {
  return {
    partsTotal: Number(data?.parts_total || 0),
    messageId: String(data?.message_id || ''),
    deliveryState: String(data?.delivery_state || 'pending'),
    message: String(data?.message || '短信已提交，等待运营商回执')
  }
}

function parseTs(s: string) {
  const ms = new Date(s).getTime()
  return Number.isFinite(ms) ? ms : 0
}

function normalizeThread(contact: SMSContactDTO): SmsThreadVM {
  return {
    key: `${contact.imsi}|${contact.peer}`,
    imsi: contact.imsi,
    peer: contact.peer,
    deviceId: contact.device_id,
    lastTs: parseTs(contact.last_timestamp),
    lastSmsId: contact.last_sms_id || 0,
    lastMessage: String(contact.last_content || '').slice(0, 80),
    lastDeviceName: contact.device_name,
    localPhone: contact.local_phone || '',
    peerLower: String(contact.peer || '').toLowerCase(),
    lastMessageLower: String(contact.last_content || '').toLowerCase()
  }
}

const inflightRequests = new Map<string, Promise<ServiceResult<unknown>>>()

function reuseInflight<T>(key: string, task: () => Promise<T>): Promise<ServiceResult<T>> {
  const existing = inflightRequests.get(key)
  if (existing) return existing as Promise<ServiceResult<T>>

  const promise = callService(task).finally(() => {
    if (inflightRequests.get(key) === promise) inflightRequests.delete(key)
  })
  inflightRequests.set(key, promise as Promise<ServiceResult<unknown>>)
  return promise
}

export const smsService = {
  listDevices() {
    return reuseInflight('sms:listDevices', async () => {
      const res = await api.get('/devices')
      const list = (res.data?.devices || []) as DeviceMgmtListItem[]
      // SMS 已是系统不变量（恒开），不再按 sms_enabled 过滤；仅展示运行中设备。
      return list.filter(d => d.running)
    })
  },
  listContacts(deviceId?: string) {
    const key = `sms:listContacts:${deviceId && deviceId !== 'all' ? deviceId : 'all'}`
    return reuseInflight(key, async () => {
      const params: Record<string, string> = { limit: '200' }
      if (deviceId && deviceId !== 'all') params.device_id = deviceId
      const res = await api.get('/sms/contacts', { params })
      const list = (res.data || []) as SMSContactDTO[]
      return list.map(normalizeThread).sort((a, b) => b.lastTs - a.lastTs)
    })
  },
  getThread(params: SmsThreadQueryParams) {
    const key = `sms:getThread:${params.device_id || ''}:${params.imsi || ''}:${params.peer}:${params.limit}:${params.before_ts || ''}:${params.before_id || 0}`
    return reuseInflight(key, async () => {
      const res = await api.get('/sms/thread', { params })
      const list = (res.data || []) as SMSMessageDTO[]
      return list.slice().sort((a, b) => parseTs(a.timestamp) - parseTs(b.timestamp) || a.id - b.id)
    })
  },
  async send(payload: SmsSendPayload): Promise<ServiceResult<SmsSendResult>> {
    try {
      const res = await api.post<SmsSendAPIResponse>('/sms/send', payload)
      return ok(normalizeSmsSendResponse(res.data))
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.data && typeof err.response.data === 'object') {
        const data = err.response.data as SmsSendAPIResponse
        if (String(data.message_id || '').trim()) {
          return ok(normalizeSmsSendResponse(data))
        }
      }
      return fail(toAppError(err))
    }
  },
  getDelivery(messageId: string) {
    return callService(async () => {
      const res = await api.get<{ delivery?: Record<string, unknown> }>(`/sms/delivery/${encodeURIComponent(messageId)}`)
      const delivery = res.data?.delivery || {}
      const rawParts = delivery.parts ?? delivery.Parts
      const parts = Array.isArray(rawParts) ? rawParts as Array<Record<string, unknown>> : []
      const failedPart = parts.find(part => {
        const state = String((part.state ?? part.State) || '')
        return state === 'failed' || state === 'delivery_failed'
      })
      return {
        state: String((delivery.state ?? delivery.State) || 'pending'),
        acks: Number((delivery.acks ?? delivery.Acks) || 0),
        partsTotal: Number((delivery.parts_total ?? delivery.PartsTotal) || 0),
        failedPartCause: failedPart ? Number((failedPart.rp_cause ?? failedPart.RPCause) || 0) : undefined
      } satisfies SmsDeliveryResult
    })
  },
  deleteMessage(id: number) {
    return callService(async () => {
      const res = await api.delete('/sms/messages/' + id)
      return res.data as { thread_empty: boolean; imsi: string; peer: string }
    })
  },
  deleteThread(payload: SmsDeleteThreadPayload) {
    return callService(async () => {
      const params: Record<string, string> = { peer: payload.peer }
      if (payload.device_id) params.device_id = payload.device_id
      if (payload.imsi) params.imsi = payload.imsi
      const res = await api.delete('/sms/thread', { params })
      return res.data as { deleted: number; imsi: string; peer: string }
    })
  }
}
