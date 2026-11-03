import test from 'node:test'
import assert from 'node:assert/strict'
import {
  statusLightAnimatedClass,
  statusLightSizeClass,
  statusLightToneClass,
  type StatusLightTone,
} from '../src/components/statusLight'

// Tailwind spacing: the numeric suffix is in 0.25rem units, so w-1.5 = 6px and
// w-2.5 = 10px. Parsing it lets the test assert the ORDERING rather than pinning
// exact class names, which would break on any legitimate resize.
function widthPx(cls: string): number {
  const m = cls.match(/\bw-(\d+(?:\.\d+)?)\b/)
  assert.ok(m, `no width utility found in "${cls}"`)
  return parseFloat(m![1]) * 4
}

test('md is larger than sm', () => {
  // Regression: these were inverted from the initial release -- 'md' returned
  // w-1.5 (6px) and 'sm' returned w-2 (8px), so DeviceCard's size="md" light
  // rendered smaller than the list lights it was meant to stand out against.
  const sm = widthPx(statusLightSizeClass('sm'))
  const md = widthPx(statusLightSizeClass('md'))
  assert.ok(md > sm, `md (${md}px) must be larger than sm (${sm}px)`)
})

test('size classes keep width and height square', () => {
  for (const size of ['sm', 'md'] as const) {
    const cls = statusLightSizeClass(size)
    const w = cls.match(/\bw-(\d+(?:\.\d+)?)\b/)?.[1]
    const h = cls.match(/\bh-(\d+(?:\.\d+)?)\b/)?.[1]
    assert.equal(w, h, `${size} must be square, got ${cls}`)
  }
})

test('every tone maps to a distinct colour', () => {
  const tones: StatusLightTone[] = ['success', 'warning', 'danger', 'neutral']
  const classes = tones.map(statusLightToneClass)
  assert.equal(new Set(classes).size, tones.length, 'tones must be visually distinguishable')
  for (const c of classes) {
    assert.match(c!, /^bg-/, 'tone must resolve to a background utility')
  }
})

test('state tones use the semantic ramps, not the accent', () => {
  // The accent marks things the operator can act on; a status light reports state.
  for (const tone of ['success', 'warning', 'danger'] as const) {
    assert.doesNotMatch(statusLightToneClass(tone)!, /primary/)
  }
})

test('animation is opt-out and produces no class when off', () => {
  assert.equal(statusLightAnimatedClass(true), 'animate-pulse')
  assert.equal(statusLightAnimatedClass(false), '')
})
