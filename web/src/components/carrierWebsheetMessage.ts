export type CarrierWebsheetCallback = {
  source: 'vowifi' | 'odsa'
  controller?: string
  method?: string
  event: string
  resultCode?: string
  href?: string
  activationCode?: string
  defaultSmdpAddress?: string
  smdpFqdn?: string
  iccid?: string
  imei?: string
  nextAction?: string
}

export type CarrierWebsheetMessageContext = {
  iframeWindow: unknown
  sessionId: string
  nonce: string
}

type MessageEventLike = {
  origin?: unknown
  source?: unknown
  data?: unknown
}

const callbackLimits: Readonly<Record<keyof CarrierWebsheetCallback, number>> = {
  source: 16,
  controller: 128,
  method: 128,
  event: 128,
  resultCode: 128,
  href: 2048,
  activationCode: 2048,
  defaultSmdpAddress: 512,
  smdpFqdn: 255,
  iccid: 64,
  imei: 64,
  nextAction: 256
}

const messageKeys = new Set(['type', 'sessionId', 'nonce', 'callback'])
const callbackKeys = new Set(Object.keys(callbackLimits))

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function hasOnlyKeys(record: Record<string, unknown>, allowed: ReadonlySet<string>) {
  return Object.keys(record).every(key => allowed.has(key))
}

function hasControlCharacter(value: string) {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) return true
  }
  return false
}

function isValidString(value: unknown, max: number, required = false) {
  if (value === undefined && !required) return true
  if (typeof value !== 'string') return false
  if (required && value.trim() === '') return false
  return value.length <= max && !hasControlCharacter(value)
}

function validatedCallback(value: unknown): CarrierWebsheetCallback | null {
  if (!isRecord(value) || !hasOnlyKeys(value, callbackKeys)) return null
  if (!Object.hasOwn(value, 'source') || !Object.hasOwn(value, 'event')) return null
  if (value.source !== 'vowifi' && value.source !== 'odsa') return null
  if (!isValidString(value.event, callbackLimits.event, true)) return null

  for (const [key, max] of Object.entries(callbackLimits)) {
    if (key === 'source' || key === 'event') continue
    if (!isValidString(value[key], max)) return null
  }
  return value as CarrierWebsheetCallback
}

export function validateCarrierWebsheetMessage(
  event: MessageEventLike,
  context: CarrierWebsheetMessageContext
): CarrierWebsheetCallback | null {
  if (
    event.origin !== 'null' ||
    event.source !== context.iframeWindow ||
    context.iframeWindow == null ||
    context.sessionId === '' ||
    context.nonce === ''
  ) {
    return null
  }

  if (!isRecord(event.data) || !hasOnlyKeys(event.data, messageKeys)) return null
  if (Object.keys(event.data).length !== messageKeys.size) return null
  if (
    event.data.type !== 'vohive-websheet-callback' ||
    event.data.sessionId !== context.sessionId ||
    event.data.nonce !== context.nonce
  ) {
    return null
  }

  return validatedCallback(event.data.callback)
}
