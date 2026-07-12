import { api } from '../stores/auth'
import { callService } from './http'

export type DocsLinks = {
  swagger_ui: string
  openapi_yaml: string
  openapi_json: string
}

export type UpdateInfo = {
  has_update: boolean
  current_version: string
  latest_version: string
  release_note: string
  is_docker: boolean
}

export type SystemInfo = {
  version: string
  build_time: string
  config: string
  docs: DocsLinks
}

export type TelegramSettings = {
  enabled: boolean
  bot_token: string
  chat_id: number | null
  admin_id: number | null
  base_url: string
  proxy: string
}

export type FeishuSettings = {
  enabled: boolean
  app_id: string
  app_secret: string
  chat_ids: string[]
}

export type QQSettings = {
  enabled: boolean
  app_id: string
  app_secret: string
  group_ids: string
  direct_ids: string
}

export type WebhookSettings = {
  enabled: boolean
  urls: string[]
  secret: string
  timeout_ms: number
  retry_max: number
  text_template: string
  headers: Record<string, string>
}

export type BarkSettings = {
  enabled: boolean
  urls: string[]
  group: string
  icon: string
  level: string
}

export type EmailSettings = {
  enabled: boolean
  use_ssl: boolean
  smtp_host: string
  smtp_port: number
  username: string
  password: string
  from_address: string
  to_addresses: string[]
}

export type PushplusSettings = {
  enabled: boolean
  token: string
  topic: string
  channel: string
}

export type NotificationsSettingsResponse = {
  telegram?: Partial<TelegramSettings>
  feishu?: Partial<FeishuSettings>
  qq?: Partial<QQSettings>
  email?: Partial<EmailSettings>
  pushplus?: Partial<PushplusSettings>
  webhook?: Partial<WebhookSettings>
  bark?: Partial<BarkSettings>
}

export type SaveNotificationsPayload = {
  telegram: {
    enabled: boolean
    bot_token: string
    chat_id: number
    admin_id: number
    base_url: string
    proxy: string
  }
  feishu: {
    enabled: boolean
    app_id: string
    app_secret: string
    chat_ids: string[]
  }
  qq: {
    enabled: boolean
    app_id: string
    app_secret: string
    group_ids: string
    direct_ids: string
  }
  email: {
    enabled: boolean
    use_ssl: boolean
    smtp_host: string
    smtp_port: number
    username: string
    password: string
    from_address: string
    to_addresses: string[]
  }
  pushplus: {
    enabled: boolean
    token: string
    topic: string
    channel: string
  }
  webhook: {
    enabled: boolean
    urls: string[]
    secret: string
    timeout_ms: number
    retry_max: number
    text_template: string
    headers?: Record<string, string>
  }
  bark: {
    enabled: boolean
    urls: string[]
    group: string
    icon: string
    level: string
  }
}

export type SaveNotificationsResponse = {
  applied?: boolean
  warning?: string
}

export type TestWebhookPayload = {
  enabled: boolean
  urls: string[]
  secret: string
  timeout_ms: number
  retry_max: number
  text_template: string
  headers?: Record<string, string>
}

export type TestWebhookResponse = {
  ok: boolean
  message: string
  failed_urls?: string[]
}

export type TestBarkPayload = {
  enabled: boolean
  urls: string[]
  group: string
  icon: string
  level: string
}

export type TestBarkResponse = {
  ok: boolean
  message: string
  failed_urls?: string[]
}

export type TestEmailPayload = {
  enabled: boolean
  use_ssl: boolean
  smtp_host: string
  smtp_port: number
  username: string
  password: string
  from_address: string
  to_addresses: string[]
}

export type TestEmailResponse = {
  ok: boolean
  message: string
}

export const systemService = {
  getInfo() {
    return callService(async () => {
      const res = await api.get('/system/info')
      return res.data as SystemInfo
    })
  },
  changePassword(payload: { old_password: string; new_password: string; confirm_password: string }) {
    return callService(async () => {
      await api.post('/settings/password', payload)
      return true
    })
  },
  getNotifications() {
    return callService(async () => {
      const res = await api.get('/settings/notifications')
      return (res.data || {}) as NotificationsSettingsResponse
    })
  },
  saveNotifications(payload: SaveNotificationsPayload) {
    return callService(async () => {
      const res = await api.put<SaveNotificationsResponse>('/settings/notifications', payload)
      return {
        applied: res.data?.applied,
        warning: res.data?.warning
      }
    })
  },
  testWebhook(payload: TestWebhookPayload) {
    return callService(async () => {
      const res = await api.post<TestWebhookResponse>('/settings/notifications/webhook/test', payload)
      return res.data
    })
  },
  testBark(payload: TestBarkPayload) {
    return callService(async () => {
      const res = await api.post<TestBarkResponse>('/settings/notifications/bark/test', payload)
      return res.data
    })
  },
  testEmail(payload: TestEmailPayload) {
    return callService(async () => {
      const res = await api.post<TestEmailResponse>('/settings/notifications/email/test', payload)
      return res.data
    })
  },
  checkUpdate() {
    return callService(async () => {
      const res = await api.get<UpdateInfo>('/system/update/check')
      return res.data
    })
  },
  applyUpdate() {
    return callService(async () => {
      const res = await api.post<{ message: string }>('/system/update/apply', {})
      return res.data
    })
  }
}
