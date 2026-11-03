import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

const source = await readFile(
  new URL('../src/components/DeviceConfigTab.vue', import.meta.url),
  'utf8'
)

test('AT 端口 field is read-only (no manual write to editConfig.at_port)', () => {
  // 不应再有把输入写回 editConfig.at_port 的处理器
  assert.doesNotMatch(source, /editConfig\.at_port\s*=/)
})

test('AT 端口 input is disabled like other auto-probed path fields', () => {
  // 截取 <label>AT 端口</label> 之后的输入块,断言其 disabled
  const idx = source.indexOf('>AT 端口<')
  assert.ok(idx >= 0, 'AT 端口 label not found in template')
  const after = source.slice(idx, idx + 200)
  assert.match(after, /disabled/)
})

test('activeATPort prefers runtime deviceStatus value', () => {
  assert.match(
    source,
    /activeATPort\s*=\s*computed\(\(\)\s*=>\s*props\.deviceStatus\?\.at_port\s*\|\|\s*props\.editConfig\?\.at_port\)/
  )
})
