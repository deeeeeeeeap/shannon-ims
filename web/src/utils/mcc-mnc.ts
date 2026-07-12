export type MccMncRow = {
  mcc: string
  mnc: string
  iso: string
  country: string
  country_code: string
  network: string
}

export type ServingOperatorLike = {
  operator?: string
  mcc?: string
  mnc?: string
}

const TABLE_URL = 'https://raw.githubusercontent.com/musalbas/mcc-mnc-table/refs/heads/master/mcc-mnc-table.json'
const STORAGE_KEY = 'go-4gproxy:mcc-mnc-table:v1'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000

type CachePayload = {
  fetched_at: number
  rows: MccMncRow[]
}

let indexPromise: Promise<Map<string, MccMncRow>> | null = null

function isAllDigits(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 48 || c > 57) return false
  }
  return s.length > 0
}

function normalizeCode(s: string): string {
  return String(s || '').trim()
}

function buildIndex(rows: MccMncRow[]): Map<string, MccMncRow> {
  const idx = new Map<string, MccMncRow>()
  for (const r of rows) {
    const mcc = normalizeCode(r?.mcc)
    const mnc = normalizeCode(r?.mnc)
    if (!mcc || !mnc) continue
    const key = `${mcc}${mnc}`
    if (!idx.has(key)) {
      idx.set(key, {
        mcc,
        mnc,
        iso: normalizeCode(r?.iso).toLowerCase(),
        country: normalizeCode(r?.country),
        country_code: normalizeCode(r?.country_code),
        network: normalizeCode(r?.network)
      })
      continue
    }
    const cur = idx.get(key)!
    if (!cur.network && r?.network) {
      cur.network = normalizeCode(r.network)
    }
  }
  return idx
}

function readCache(): CachePayload | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const data = JSON.parse(raw) as CachePayload
    if (!data || !Array.isArray(data.rows) || typeof data.fetched_at !== 'number') return null
    return data
  } catch {
    return null
  }
}

function writeCache(rows: MccMncRow[]) {
  try {
    const payload: CachePayload = { fetched_at: Date.now(), rows }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload))
  } catch {
    // Ignore cache write failures (private mode/quota/security policy).
  }
}

async function fetchRows(): Promise<MccMncRow[]> {
  const res = await fetch(TABLE_URL, { method: 'GET' })
  if (!res.ok) throw new Error(`mcc-mnc-table fetch failed: ${res.status}`)
  const data = await res.json()
  if (!Array.isArray(data)) return []
  const out: MccMncRow[] = []
  for (const it of data) {
    if (!it || typeof it !== 'object') continue
    const r = it as Record<string, unknown>
    const mcc = typeof r.mcc === 'string' ? r.mcc : ''
    const mnc = typeof r.mnc === 'string' ? r.mnc : ''
    if (!mcc || !mnc) continue
    out.push({
      mcc,
      mnc,
      iso: typeof r.iso === 'string' ? r.iso : '',
      country: typeof r.country === 'string' ? r.country : '',
      country_code: typeof r.country_code === 'string' ? r.country_code : '',
      network: typeof r.network === 'string' ? r.network : ''
    })
  }
  return out
}

export async function getMccMncIndex(): Promise<Map<string, MccMncRow>> {
  if (indexPromise) return indexPromise
  indexPromise = (async () => {
    const cache = readCache()
    const now = Date.now()
    if (cache && cache.rows.length > 0 && now - cache.fetched_at < CACHE_TTL_MS) {
      return buildIndex(cache.rows)
    }
    try {
      const rows = await fetchRows()
      if (rows.length > 0) writeCache(rows)
      return buildIndex(rows)
    } catch {
      if (cache && cache.rows.length > 0) {
        return buildIndex(cache.rows)
      }
      return new Map()
    }
  })()
  return indexPromise
}

export function isoToFlagEmoji(iso: string): string {
  const s = normalizeCode(iso).toUpperCase()
  if (s.length !== 2) return ''
  const a = s.charCodeAt(0)
  const b = s.charCodeAt(1)
  if (a < 65 || a > 90 || b < 65 || b > 90) return ''
  return String.fromCodePoint(0x1f1e6 + (a - 65)) + String.fromCodePoint(0x1f1e6 + (b - 65))
}

export function getMncCandidateLengths(mcc: string): number[] {
  const m3 = [
    '302', '308', // 加拿大等
    '310', '311', '312', '313', '314', '315', '316', '332', '318', '319', '334', '350', // 美国及属地
    '338', '348', '342', '344', '346', '354', '356', '358', '360', '362', '364', '365', '366', '368', '370', '372', '374', '376',
    '405', '406', // 印度 (部分)
    '716', '722', '730', '732', '736', '740', '744', '746', '748', '750', // 南美洲
  ]
  if (m3.includes(mcc)) return [3]
  return [2, 3] // 其他地区默认优先 2位, 然后是3位
}

export function lookupServingOperatorNameFromPLMN(index: Map<string, MccMncRow>, modem: ServingOperatorLike): MccMncRow | null {
  const op = normalizeCode(modem?.operator || '')
  if (op && (op.length === 5 || op.length === 6) && isAllDigits(op)) {
    const hit = index.get(op)
    if (hit) return hit
  }

  const mcc = normalizeCode(modem?.mcc || '')
  const mnc = normalizeCode(modem?.mnc || '')
  if (mcc && mnc) {
    const hit = index.get(`${mcc}${mnc}`)
    if (hit) return hit
  }

  return null
}

export function formatServingOperatorDisplay(modem: ServingOperatorLike, index: Map<string, MccMncRow> | null): string {
  const op = normalizeCode(modem?.operator || '')
  if (!index) return op || '--'
  const row = lookupServingOperatorNameFromPLMN(index, modem)
  if (!row) return op || '--'
  const flag = isoToFlagEmoji(row.iso)
  const name = normalizeCode(row.network) || normalizeCode(row.country) || '--'
  const code = `${normalizeCode(row.mcc)}${normalizeCode(row.mnc)}`
  return `${flag ? flag + ' ' : ''}${name}${code ? ` (${code})` : ''}`
}
