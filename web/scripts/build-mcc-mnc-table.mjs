#!/usr/bin/env node
// Regenerates web/public/data/mcc-mnc-table.json from the upstream MCC/MNC table.
//
// The app bundles this file rather than fetching it at runtime: the console manages
// local hardware over localhost, so a request to raw.githubusercontent.com made
// operator names unavailable on air-gapped or firewalled deployments and told a
// third party when the device page was opened.
//
// Run manually when the table should be refreshed -- PLMN assignments change slowly,
// so this is not part of the build:
//
//   node scripts/build-mcc-mnc-table.mjs
//
// Upstream (ODbL): https://github.com/musalbas/mcc-mnc-table
//
// Only the five fields the UI reads are kept, and duplicate PLMNs are collapsed
// (upstream lists some twice, occasionally with the network name on the later row).
import { writeFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const SRC = 'https://raw.githubusercontent.com/musalbas/mcc-mnc-table/refs/heads/master/mcc-mnc-table.json'
const HERE = path.dirname(fileURLToPath(import.meta.url))
const OUT = path.join(HERE, '..', 'public', 'data', 'mcc-mnc-table.json')

const str = v => (typeof v === 'string' ? v.trim() : '')

async function main() {
  const res = await fetch(SRC)
  if (!res.ok) throw new Error(`upstream fetch failed: ${res.status} ${res.statusText}`)
  const raw = await res.json()
  if (!Array.isArray(raw)) throw new Error('upstream payload is not an array')

  const rows = []
  const index = new Map()

  for (const it of raw) {
    if (!it || typeof it !== 'object') continue
    const mcc = str(it.mcc)
    const mnc = str(it.mnc)
    if (!mcc || !mnc) continue

    const key = mcc + mnc
    const network = str(it.network)
    const existing = index.get(key)
    if (existing) {
      if (!existing.network && network) existing.network = network
      continue
    }
    const row = {
      mcc,
      mnc,
      iso: str(it.iso).toLowerCase(),
      country: str(it.country),
      network,
    }
    index.set(key, row)
    rows.push(row)
  }

  if (rows.length < 1000) {
    // Guard against writing a truncated table over a good one.
    throw new Error(`only ${rows.length} usable rows; refusing to overwrite`)
  }

  rows.sort((a, b) => (a.mcc + a.mnc).localeCompare(b.mcc + b.mnc))

  mkdirSync(path.dirname(OUT), { recursive: true })
  const json = JSON.stringify(rows)
  writeFileSync(OUT, json, 'utf8')
  console.log(`wrote ${rows.length} rows, ${(Buffer.byteLength(json) / 1024).toFixed(1)} KB`)
  console.log(`  -> ${path.relative(process.cwd(), OUT)}`)
}

main().catch(err => {
  console.error(err.message)
  process.exitCode = 1
})
