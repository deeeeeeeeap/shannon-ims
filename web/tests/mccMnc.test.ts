import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

// Two things are pinned here:
//
//   1. The PLMN table is served from our own origin. This console manages local
//      hardware over localhost, and the lookup used to fetch from
//      raw.githubusercontent.com -- which made operator names unavailable on
//      air-gapped deployments and disclosed page opens to a third party.
//   2. A failed lookup degrades to the raw PLMN digits and never throws, because
//      every caller renders the result straight into the device page.

const source = await readFile(new URL('../src/utils/mcc-mnc.ts', import.meta.url), 'utf8')

test('the PLMN table is same-origin, not fetched from the internet', () => {
  assert.match(source, /const TABLE_URL = '\/data\/mcc-mnc-table\.json'/,
    'TABLE_URL must point at our own origin')

  // Check executable lines only: the comments legitimately name the upstream source
  // the bundled table was generated from, and asserting over the whole file would
  // make documenting that provenance a test failure.
  const code = source
    .split('\n')
    .filter(line => !line.trim().startsWith('//') && !line.trim().startsWith('*'))
    .join('\n')

  assert.doesNotMatch(code, /https?:\/\//,
    'no runtime code path may reference an external URL')
})

test('the bundled table exists, is well formed, and covers the validated carriers', async () => {
  const raw = await readFile(new URL('../public/data/mcc-mnc-table.json', import.meta.url), 'utf8')
  const rows = JSON.parse(raw)

  assert.ok(Array.isArray(rows), 'table must be a JSON array')
  assert.ok(rows.length > 1000, `expected a full table, got ${rows.length} rows`)

  for (const r of rows.slice(0, 50)) {
    assert.equal(typeof r.mcc, 'string')
    assert.equal(typeof r.mnc, 'string')
    assert.equal(typeof r.iso, 'string')
  }

  // PLMNs this project has validated against real hardware; a regenerated table
  // that lost them would silently degrade the device page.
  const find = (mcc: string, mnc: string) =>
    rows.find((r: { mcc: string; mnc: string }) => r.mcc === mcc && r.mnc === mnc)

  const vodafone = find('234', '15')
  assert.ok(vodafone, '234/15 (Vodafone UK) missing')
  assert.equal(vodafone.iso, 'gb')

  const tmobile = find('310', '240')
  assert.ok(tmobile, '310/240 missing')
  assert.equal(tmobile.iso, 'us')

  assert.ok(find('234', '10'), '234/10 (O2 / giffgaff host) missing')
})

test('PLMN keys are unique', async () => {
  const raw = await readFile(new URL('../public/data/mcc-mnc-table.json', import.meta.url), 'utf8')
  const rows = JSON.parse(raw) as Array<{ mcc: string; mnc: string }>
  const keys = new Set(rows.map(r => r.mcc + r.mnc))
  assert.equal(keys.size, rows.length, 'duplicate PLMN entries would make lookups order-dependent')
})

test('a lookup failure resolves to an empty index instead of rejecting', async () => {
  // The device page must survive a missing or corrupt table.
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: async () => { throw new Error('offline') },
  })
  const { getMccMncIndex } = await import('../src/utils/mcc-mnc?failure-case')
  const index = await getMccMncIndex()
  assert.ok(index instanceof Map)
  assert.equal(index.size, 0)
})

test('formatting falls back to the raw code when the name is unknown', async () => {
  const { formatServingOperatorDisplay } = await import('../src/utils/mcc-mnc')
  const empty = new Map()

  assert.equal(formatServingOperatorDisplay({ operator: '23415' }, empty), '23415',
    'unknown PLMN must still show the digits')
  assert.equal(formatServingOperatorDisplay({ operator: '' }, empty), '--')
  assert.equal(formatServingOperatorDisplay({ operator: '23415' }, null), '23415',
    'a null index must not blank the field')
})

test('a known PLMN renders flag, name and code', async () => {
  const { formatServingOperatorDisplay } = await import('../src/utils/mcc-mnc')
  const index = new Map([
    ['23415', { mcc: '234', mnc: '15', iso: 'gb', country: 'United Kingdom', network: 'Vodafone' }],
  ])
  const out = formatServingOperatorDisplay({ operator: '23415' }, index)
  assert.match(out, /Vodafone/)
  assert.match(out, /23415/)
  assert.match(out, /\u{1F1EC}\u{1F1E7}/u, 'GB flag emoji expected')
})
