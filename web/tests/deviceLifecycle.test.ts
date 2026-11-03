import test from 'node:test'
import assert from 'node:assert/strict'
import {
  isControlOnline,
  isRecoveryPhase,
  primaryLifecycleStatus,
} from '../src/utils/deviceLifecycle'

// The rule these tests pin down: a pulse means "in motion, keep watching".
// Steady states do not pulse.
//
// The regression being prevented is subtle because nothing breaks -- steady online
// used to return animated:true, so every healthy device in a list pulsed forever.
// With everything blinking there is no idle baseline, so a device that really is
// rebooting no longer stands out, which is the entire purpose of the animation.

const ONLINE = { running: true, healthy: true, control_online: true, lifecycle_phase: 'online' as const }

test('a settled device does not pulse, online or offline', () => {
  assert.equal(primaryLifecycleStatus(ONLINE).animated, false, 'steady online must not pulse')
  assert.equal(primaryLifecycleStatus({ ...ONLINE, running: false }).animated, false,
    'offline is settled too')
})

test('transitional phases pulse', () => {
  for (const phase of ['rebooting', 'usb_wait', 'worker_starting', 'qmi_starting', 'recovering', 'evicting'] as const) {
    const status = primaryLifecycleStatus({ ...ONLINE, lifecycle_phase: phase })
    assert.equal(status.animated, true, `${phase} is transitional and should pulse`)
    assert.equal(status.tone, 'warning')
  }
})

test('degraded pulses: it is unstable rather than settled', () => {
  const status = primaryLifecycleStatus({ ...ONLINE, lifecycle_phase: 'degraded' })
  assert.equal(status.animated, true)
  assert.equal(status.tone, 'warning')
})

test('online and offline are distinguishable by tone, not only by animation', () => {
  // Colour must carry the state on its own, since animation is now off for both.
  assert.equal(primaryLifecycleStatus(ONLINE).tone, 'success')
  assert.equal(primaryLifecycleStatus({ ...ONLINE, running: false }).tone, 'danger')
})

test('recovery phases are never treated as control-online', () => {
  // A rebooting device may still report running/healthy from a stale sample.
  for (const phase of ['rebooting', 'usb_wait', 'recovering'] as const) {
    assert.equal(isRecoveryPhase(phase), true)
    assert.equal(isControlOnline({ ...ONLINE, lifecycle_phase: phase }), false,
      `${phase} must not count as online`)
  }
})

test('every status carries a non-empty label', () => {
  const cases = [
    ONLINE,
    { ...ONLINE, running: false },
    { ...ONLINE, lifecycle_phase: 'degraded' as const },
    { ...ONLINE, lifecycle_phase: 'rebooting' as const },
    { ...ONLINE, control_online: false },
  ]
  for (const device of cases) {
    assert.ok(primaryLifecycleStatus(device).label.length > 0)
  }
})
