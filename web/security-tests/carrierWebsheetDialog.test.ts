import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(
  new URL('../src/components/CarrierWebsheetDialog.vue', import.meta.url),
  'utf8'
)

test('Carrier Websheet accepts only direct opaque-origin iframe messages', () => {
  assert.doesNotMatch(source, /websheetToken|BroadcastChannel|addEventListener\('storage'/)
  assert.match(source, /messageNonce/)
  assert.match(source, /event\.origin !== 'null'/)
  assert.match(source, /event\.source !== iframeEl\.value\?\.contentWindow/)

  const sandbox = source.match(/sandbox="([^"]+)"/)?.[1] ?? ''
  assert.match(sandbox, /(?:^|\s)allow-scripts(?:\s|$)/)
  assert.doesNotMatch(sandbox, /(?:^|\s)allow-same-origin(?:\s|$)/)
})
