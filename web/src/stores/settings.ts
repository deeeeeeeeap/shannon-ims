import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { AppError } from '../types/domain'
import {
  systemService,
  type NotificationsSettingsResponse,
  type SaveNotificationsPayload,
  type SaveNotificationsResponse,
  type SystemInfo,
  type TestWebhookResponse,
  type WebhookSettings,
  type BarkSettings,
  type TestBarkResponse,
  type TestEmailResponse
} from '../services/system'

const DEFAULT_SYSTEM_INFO: SystemInfo = {
  version: '',
  build_time: '',
  config: '',
  docs: {
    swagger_ui: '',
    openapi_yaml: '',
    openapi_json: ''
  }
}

type PasswordForm = {
  old_password: string
  new_password: string
  confirm_password: string
}

type TelegramForm = {
  enabled: boolean
  bot_token: string
  chat_id: number | null
  admin_id: number | null
  base_url: string
  proxy: string
}

type FeishuForm = {
  enabled: boolean
  app_id: string
  app_secret: string
  chat_ids: string
}

type QQForm = {
  enabled: boolean
  app_id: string
  app_secret: string
  group_ids: string
  direct_ids: string
}

type EmailForm = {
  enabled: boolean
  use_ssl: boolean
  smtp_host: string
  smtp_port: number | null
  username: string
  password: string
  from_address: string
  to_addresses: string
}

type PushplusForm = {
  enabled: boolean
  token: string
  topic: string
  channel: string
}

const DEFAULT_PASSWORD_FORM: PasswordForm = {
  old_password: '',
  new_password: '',
  confirm_password: ''
}

const DEFAULT_TELEGRAM_FORM: TelegramForm = {
  enabled: false,
  bot_token: '',
  chat_id: null,
  admin_id: null,
  base_url: '',
  proxy: ''
}

const DEFAULT_FEISHU_FORM: FeishuForm = {
  enabled: false,
  app_id: '',
  app_secret: '',
  chat_ids: ''
}

const DEFAULT_QQ_FORM: QQForm = {
  enabled: false,
  app_id: '',
  app_secret: '',
  group_ids: '',
  direct_ids: ''
}

const DEFAULT_EMAIL_FORM: EmailForm = {
  enabled: false,
  use_ssl: false,
  smtp_host: '',
  smtp_port: null,
  username: '',
  password: '',
  from_address: '',
  to_addresses: ''
}

const DEFAULT_PUSHPLUS_FORM: PushplusForm = {
  enabled: false,
  token: '',
  topic: '',
  channel: 'wechat'
}

const DEFAULT_WEBHOOK_SETTINGS: WebhookSettings = {
  enabled: false,
  urls: [],
  secret: '',
  timeout_ms: 5000,
  retry_max: 3,
  text_template: '{{device_label}} {{text}}',
  headers: {}
}

// 受保护的系统头（小写），与后端保持一致：自定义头不可覆盖这些
const PROTECTED_WEBHOOK_HEADERS = new Set(['content-type', 'x-vohive-signature'])

// sanitizeWebhookHeaders 去除空白 key、丢弃受保护的系统头，返回干净的 headers map
function sanitizeWebhookHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!headers) return out
  for (const [rawKey, rawVal] of Object.entries(headers)) {
    const key = String(rawKey || '').trim()
    if (!key || PROTECTED_WEBHOOK_HEADERS.has(key.toLowerCase())) continue
    out[key] = String(rawVal ?? '')
  }
  return out
}

const DEFAULT_BARK_SETTINGS: BarkSettings = {
  enabled: false,
  urls: [],
  group: 'vohive',
  icon: '',
  level: 'active'
}

export const useSettingsStore = defineStore('settings', () => {
  const systemInfo = ref<SystemInfo>({ ...DEFAULT_SYSTEM_INFO })
  const notifications = ref<NotificationsSettingsResponse>({})
  const passwordForm = ref<PasswordForm>({ ...DEFAULT_PASSWORD_FORM })
  const telegramForm = ref<TelegramForm>({ ...DEFAULT_TELEGRAM_FORM })
  const feishuForm = ref<FeishuForm>({ ...DEFAULT_FEISHU_FORM })
  const qqForm = ref<QQForm>({ ...DEFAULT_QQ_FORM })
  const webhookSettings = ref<WebhookSettings>({ ...DEFAULT_WEBHOOK_SETTINGS })
  const barkSettings = ref<BarkSettings>({ ...DEFAULT_BARK_SETTINGS })
  const emailForm = ref<EmailForm>({ ...DEFAULT_EMAIL_FORM })
  const pushplusForm = ref<PushplusForm>({ ...DEFAULT_PUSHPLUS_FORM })

  const loadingSystemInfo = ref(false)
  const loadingNotifications = ref(false)
  const savingNotifications = ref(false)
  const testingWebhook = ref(false)
  const testingBark = ref(false)
  const testingEmail = ref(false)
  const changingPassword = ref(false)

  const error = ref<AppError | null>(null)

  async function fetchSystemInfo() {
    loadingSystemInfo.value = true
    const result = await systemService.getInfo()
    if (result.ok) {
      systemInfo.value = result.data
      error.value = null
    } else {
      error.value = result.error
    }
    loadingSystemInfo.value = false
    return result
  }

  async function fetchNotifications() {
    loadingNotifications.value = true
    const result = await systemService.getNotifications()
    if (result.ok) {
      notifications.value = result.data || {}
      const tg = result.data.telegram || {}
      const fs = result.data.feishu || {}
      const qq = result.data.qq || {}
      const webhook = result.data.webhook || {}
      telegramForm.value = {
        enabled: !!tg.enabled,
        bot_token: tg.bot_token || '',
        chat_id: tg.chat_id ?? null,
        admin_id: tg.admin_id ?? null,
        base_url: tg.base_url || '',
        proxy: tg.proxy || ''
      }
      feishuForm.value = {
        enabled: !!fs.enabled,
        app_id: fs.app_id || '',
        app_secret: fs.app_secret || '',
        chat_ids: Array.isArray(fs.chat_ids) ? fs.chat_ids.join(',') : ''
      }
      qqForm.value = {
        enabled: !!qq.enabled,
        app_id: qq.app_id || '',
        app_secret: qq.app_secret || '',
        group_ids: qq.group_ids || '',
        direct_ids: qq.direct_ids || ''
      }
      webhookSettings.value = {
        enabled: !!webhook.enabled,
        urls: Array.isArray(webhook.urls) ? webhook.urls : [],
        secret: webhook.secret || '',
        timeout_ms: webhook.timeout_ms ?? 5000,
        retry_max: webhook.retry_max ?? 3,
        text_template: webhook.text_template ?? '{{device_label}} {{text}}',
        headers: webhook.headers && typeof webhook.headers === 'object' ? { ...webhook.headers } : {}
      }
      const bark = result.data.bark || {}
      barkSettings.value = {
        enabled: !!bark.enabled,
        urls: Array.isArray(bark.urls) ? bark.urls : [],
        group: bark.group || 'vohive',
        icon: bark.icon || '',
        level: bark.level || 'active'
      }
      const email = result.data.email || {}
      emailForm.value = {
        enabled: !!email.enabled,
        use_ssl: !!email.use_ssl,
        smtp_host: email.smtp_host || '',
        smtp_port: email.smtp_port ?? null,
        username: email.username || '',
        password: email.password || '',
        from_address: email.from_address || '',
        to_addresses: Array.isArray(email.to_addresses) ? email.to_addresses.join(',') : ''
      }
      const pushplus = result.data.pushplus || {}
      pushplusForm.value = {
        enabled: !!pushplus.enabled,
        token: pushplus.token || '',
        topic: pushplus.topic || '',
        channel: pushplus.channel || 'wechat'
      }
      error.value = null
    } else {
      error.value = result.error
    }
    loadingNotifications.value = false
    return result
  }

  async function saveNotifications(payload: SaveNotificationsPayload) {
    savingNotifications.value = true
    const result = await systemService.saveNotifications(payload)
    if (!result.ok) {
      error.value = result.error
    }
    savingNotifications.value = false
    return result as { ok: true; data: SaveNotificationsResponse } | { ok: false; error: AppError }
  }

  function buildNotificationsPayload(): SaveNotificationsPayload {
    return {
      telegram: {
        enabled: !!telegramForm.value.enabled,
        bot_token: telegramForm.value.bot_token || '',
        chat_id: telegramForm.value.chat_id ? Number(telegramForm.value.chat_id) : 0,
        admin_id: telegramForm.value.admin_id ? Number(telegramForm.value.admin_id) : 0,
        base_url: telegramForm.value.base_url || '',
        proxy: telegramForm.value.proxy || ''
      },
      feishu: {
        enabled: !!feishuForm.value.enabled,
        app_id: feishuForm.value.app_id || '',
        app_secret: feishuForm.value.app_secret || '',
        chat_ids: feishuForm.value.chat_ids
          ? feishuForm.value.chat_ids.split(',').map(s => s.trim()).filter(Boolean)
          : []
      },
      qq: {
        enabled: !!qqForm.value.enabled,
        app_id: qqForm.value.app_id || '',
        app_secret: qqForm.value.app_secret || '',
        group_ids: qqForm.value.group_ids || '',
        direct_ids: qqForm.value.direct_ids || ''
      },
      email: {
        enabled: !!emailForm.value.enabled,
        use_ssl: !!emailForm.value.use_ssl,
        smtp_host: emailForm.value.smtp_host || '',
        smtp_port: Number(emailForm.value.smtp_port) || 0,
        username: emailForm.value.username || '',
        password: emailForm.value.password || '',
        from_address: emailForm.value.from_address || '',
        to_addresses: emailForm.value.to_addresses
          ? emailForm.value.to_addresses.split(',').map(s => s.trim()).filter(Boolean)
          : []
      },
      pushplus: {
        enabled: !!pushplusForm.value.enabled,
        token: pushplusForm.value.token || '',
        topic: pushplusForm.value.topic || '',
        channel: pushplusForm.value.channel || ''
      },
      webhook: {
        enabled: !!webhookSettings.value.enabled,
        urls: Array.isArray(webhookSettings.value.urls) ? webhookSettings.value.urls : [],
        secret: webhookSettings.value.secret || '',
        timeout_ms: Number(webhookSettings.value.timeout_ms) || 5000,
        retry_max: Number(webhookSettings.value.retry_max) || 3,
        text_template: String(webhookSettings.value.text_template || ''),
        headers: sanitizeWebhookHeaders(webhookSettings.value.headers)
      },
      bark: {
        enabled: !!barkSettings.value.enabled,
        urls: Array.isArray(barkSettings.value.urls) ? barkSettings.value.urls : [],
        group: String(barkSettings.value.group || '').trim(),
        icon: String(barkSettings.value.icon || '').trim(),
        level: String(barkSettings.value.level || '').trim()
      }
    }
  }

  async function saveNotificationsFromForms() {
    return saveNotifications(buildNotificationsPayload())
  }

  async function testWebhookFromForm() {
    testingWebhook.value = true
    const payload = {
      enabled: !!webhookSettings.value.enabled,
      urls: (Array.isArray(webhookSettings.value.urls) ? webhookSettings.value.urls : [])
        .map(s => String(s || '').trim())
        .filter(Boolean),
      secret: webhookSettings.value.secret || '',
      timeout_ms: Number(webhookSettings.value.timeout_ms) || 5000,
      retry_max: Number(webhookSettings.value.retry_max) || 3,
      text_template: String(webhookSettings.value.text_template || ''),
      headers: sanitizeWebhookHeaders(webhookSettings.value.headers)
    }
    const result = await systemService.testWebhook(payload)
    if (!result.ok) {
      error.value = result.error
    }
    testingWebhook.value = false
    return result as { ok: true; data: TestWebhookResponse } | { ok: false; error: AppError }
  }

  async function testBarkFromForm() {
    testingBark.value = true
    const payload = {
      enabled: !!barkSettings.value.enabled,
      urls: (Array.isArray(barkSettings.value.urls) ? barkSettings.value.urls : [])
        .map(s => String(s || '').trim())
        .filter(Boolean),
      group: String(barkSettings.value.group || '').trim(),
      icon: String(barkSettings.value.icon || '').trim(),
      level: String(barkSettings.value.level || '').trim()
    }
    const result = await systemService.testBark(payload)
    if (!result.ok) {
      error.value = result.error
    }
    testingBark.value = false
    return result as { ok: true; data: TestBarkResponse } | { ok: false; error: AppError }
  }

  async function testEmailFromForm() {
    testingEmail.value = true
    const payload = {
      enabled: !!emailForm.value.enabled,
      use_ssl: !!emailForm.value.use_ssl,
      smtp_host: String(emailForm.value.smtp_host || '').trim(),
      smtp_port: Number(emailForm.value.smtp_port) || 0,
      username: String(emailForm.value.username || '').trim(),
      password: String(emailForm.value.password || '').trim(),
      from_address: String(emailForm.value.from_address || '').trim(),
      to_addresses: emailForm.value.to_addresses
        ? emailForm.value.to_addresses.split(',').map(s => s.trim()).filter(Boolean)
        : []
    }
    const result = await systemService.testEmail(payload)
    if (!result.ok) {
      error.value = result.error
    }
    testingEmail.value = false
    return result as { ok: true; data: TestEmailResponse } | { ok: false; error: AppError }
  }

  async function changePassword(payload: { old_password: string; new_password: string; confirm_password: string }) {
    changingPassword.value = true
    const result = await systemService.changePassword(payload)
    if (!result.ok) {
      error.value = result.error
    }
    changingPassword.value = false
    return result
  }

  async function changePasswordFromForm() {
    return changePassword(passwordForm.value)
  }

  function resetPasswordForm() {
    passwordForm.value = { ...DEFAULT_PASSWORD_FORM }
  }

  return {
    systemInfo,
    notifications,
    passwordForm,
    telegramForm,
    feishuForm,
    qqForm,
    webhookSettings,
    barkSettings,
    emailForm,
    pushplusForm,
    loadingSystemInfo,
    loadingNotifications,
    savingNotifications,
    testingWebhook,
    testingBark,
    testingEmail,
    changingPassword,
    error,
    fetchSystemInfo,
    fetchNotifications,
    saveNotifications,
    saveNotificationsFromForms,
    testWebhookFromForm,
    testBarkFromForm,
    testEmailFromForm,
    changePassword,
    changePasswordFromForm,
    resetPasswordForm
  }
})
