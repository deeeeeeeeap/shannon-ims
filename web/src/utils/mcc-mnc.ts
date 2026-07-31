// country_code is intentionally absent: nothing outside this module ever read it,
// so the bundled table drops the column. (Proxy.vue's country_code belongs to the
// unrelated upstream-proxy rule type in types/api.ts.)
export type MccMncRow = {
  mcc: string
  mnc: string
  iso: string
  country: string
  network: string
}

export type ServingOperatorLike = {
  operator?: string
  mcc?: string
  mnc?: string
}

// Served from our own origin, not raw.githubusercontent.com.
//
// This console manages local hardware over localhost, so reaching out to GitHub to
// render an operator name meant the feature silently degraded to bare PLMN digits
// on any air-gapped or firewalled deployment -- and disclosed to a third party when
// the operator opened the device page. The table is now a build asset
// (web/public/data/, 172 KB, 2126 rows, generated from the same upstream source).
//
// The localStorage cache and its TTL are gone with the network request: a
// same-origin static file is already served from the HTTP cache, so a second layer
// only added a way for the two to disagree.
const TABLE_URL = '/data/mcc-mnc-table.json'

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
      network: typeof r.network === 'string' ? r.network : ''
    })
  }
  return out
}

/**
 * Loads the PLMN table once per page and memoises the result.
 *
 * On failure it resolves to an empty Map rather than rejecting: callers use the
 * index only to prettify a PLMN code, and every one of them already falls back to
 * showing the raw digits. A missing operator name must never take out the device
 * page around it.
 */
export async function getMccMncIndex(): Promise<Map<string, MccMncRow>> {
  if (indexPromise) return indexPromise
  indexPromise = (async () => {
    try {
      return buildIndex(await fetchRows())
    } catch {
      return new Map<string, MccMncRow>()
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
