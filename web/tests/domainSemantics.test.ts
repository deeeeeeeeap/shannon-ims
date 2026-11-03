import test from 'node:test'
import assert from 'node:assert/strict'
import {
  hasValidSignalDbm,
  signalBars,
  signalQuality,
  SIGNAL_BAR_COUNT,
} from '../src/domain/signalQuality'
import {
  smsDeliveryPresentation,
  SMS_STATUS_ACCEPTED,
  SMS_STATUS_AWAITING_REPORT,
  SMS_STATUS_DELIVERED,
  SMS_STATUS_FAILED,
} from '../src/domain/smsDelivery'
import {
  blockingStage,
  readinessStages,
  readinessStatus,
  readinessSummary,
} from '../src/domain/vowifiReadiness'

// ---------------------------------------------------------------- signal quality

test('signal grading is single-valued: one reading yields one rating', () => {
  // The regression this locks: DeviceCard graded green above -70 while
  // DeviceOverviewTab graded green at -85, so -80 dBm showed amber on the
  // dashboard and green on the detail page.
  assert.equal(signalQuality(-80), 'excellent')
  assert.equal(signalBars(-80), 4)
})

test('signal bands are ordered and cover the LTE RSRP range', () => {
  assert.equal(signalQuality(-60), 'excellent')
  assert.equal(signalQuality(-85), 'excellent', 'boundary is inclusive')
  assert.equal(signalQuality(-86), 'good')
  assert.equal(signalQuality(-100), 'good')
  assert.equal(signalQuality(-101), 'fair')
  assert.equal(signalQuality(-110), 'fair')
  assert.equal(signalQuality(-111), 'poor')
  assert.equal(signalQuality(-130), 'poor')
})

test('bars decrease monotonically as signal weakens', () => {
  const readings = [-60, -90, -105, -120]
  const bars = readings.map(signalBars)
  for (let i = 1; i < bars.length; i++) {
    assert.ok(bars[i] < bars[i - 1], `bars must fall from ${readings[i - 1]} to ${readings[i]}`)
  }
  assert.ok(bars.every(b => b >= 1 && b <= SIGNAL_BAR_COUNT))
})

test('"no reading" is distinct from "very weak"', () => {
  // A dead radio must not render as one faint bar.
  for (const absent of [null, undefined, 0, -999, NaN]) {
    assert.equal(hasValidSignalDbm(absent as number), false, `${absent} is not a reading`)
    assert.equal(signalQuality(absent as number), 'unknown')
    assert.equal(signalBars(absent as number), 0)
  }
  assert.equal(signalBars(-130), 1, 'a real weak reading still shows one bar')
})

// ----------------------------------------------------------------- SMS delivery

test('SMSC acceptance is never presented as delivery', () => {
  // The project's central SMS invariant: submit_report_success means the SMSC
  // accepted the message, NOT that the handset received it.
  const accepted = smsDeliveryPresentation(2, SMS_STATUS_ACCEPTED)
  const delivered = smsDeliveryPresentation(2, SMS_STATUS_DELIVERED)

  assert.equal(accepted.kind, 'accepted')
  assert.equal(delivered.kind, 'delivered')
  assert.notEqual(accepted.glyph, delivered.glyph, 'glyphs must differ')
  assert.notEqual(accepted.toneClass, delivered.toneClass, 'colours must differ')

  // Only the delivered wording may assert the handset got it.
  assert.match(delivered.description, /收到/)
  assert.match(accepted.description, /不代表收件人已收到/)
})

test('accepted state does not borrow the accent colour', () => {
  // The accent marks things the operator can act on; "accepted" is a waypoint.
  const accepted = smsDeliveryPresentation(2, SMS_STATUS_ACCEPTED)
  assert.doesNotMatch(accepted.toneClass, /primary/)
})

test('every delivery state carries a non-empty description for assistive tech', () => {
  for (const status of [
    SMS_STATUS_ACCEPTED,
    SMS_STATUS_AWAITING_REPORT,
    SMS_STATUS_DELIVERED,
    SMS_STATUS_FAILED,
  ]) {
    const p = smsDeliveryPresentation(2, status)
    assert.ok(p.description.length > 0, `status ${status} needs a description`)
    assert.ok(p.glyph.length > 0, `status ${status} needs a glyph`)
  }
})

test('incoming messages and unknown statuses render nothing', () => {
  assert.equal(smsDeliveryPresentation(1, SMS_STATUS_DELIVERED).kind, 'none',
    'incoming messages have no delivery state')
  assert.equal(smsDeliveryPresentation(2, 99).kind, 'none')
  assert.equal(smsDeliveryPresentation(2, undefined).kind, 'none')
})

// ------------------------------------------------------------ VoWiFi readiness

const FULL = {
  sim_ready: true, access_ready: true, tunnel_ready: true, ims_ready: true, sms_ready: true,
}

test('readiness chain reports the FIRST unready stage, not just a count', () => {
  // "stalled at Tunnel" and "stalled at SMS" need different operator responses;
  // the old some()/every() summary collapsed both into "partial".
  const stalledAtTunnel = { sim_ready: true, access_ready: true, tunnel_ready: false, ims_ready: false, sms_ready: false }
  const stalledAtSms = { ...FULL, sms_ready: false }

  assert.equal(blockingStage(stalledAtTunnel)?.key, 'Tunnel')
  assert.equal(blockingStage(stalledAtSms)?.key, 'SMS')
  assert.notEqual(readinessSummary(stalledAtTunnel), readinessSummary(stalledAtSms))
})

test('exactly one stage is marked blocking', () => {
  const partial = { sim_ready: true, access_ready: false, tunnel_ready: false, ims_ready: false, sms_ready: false }
  assert.equal(readinessStages(partial).filter(s => s.blocking).length, 1)
})

test('fully ready chain has no blocking stage', () => {
  assert.equal(blockingStage(FULL), null)
  assert.equal(readinessStatus(FULL), 'ready')
  assert.equal(readinessSummary(FULL), '全部就绪')
})

test('IMS ready without SMS ready is a distinct, reportable state', () => {
  // IMSReady and SMSReady are separate states by design: a registered device with
  // no messaging capability is a real diagnostic condition, not a rounding error.
  const imsOnly = { ...FULL, sms_ready: false }
  assert.equal(readinessStatus(imsOnly), 'progressing')
  assert.equal(blockingStage(imsOnly)?.key, 'SMS')
  assert.match(readinessSummary(imsOnly), /短信就绪/)
})

test('a runtime fault separates "stalled" from "progressing"', () => {
  const partial = { sim_ready: true, access_ready: true, tunnel_ready: false, ims_ready: false, sms_ready: false }
  assert.equal(readinessStatus(partial), 'progressing', 'no error reported -> worth waiting out')
  assert.equal(readinessStatus({ ...partial, last_error_class: 'ike_auth' }), 'stalled')
  assert.equal(readinessStatus({ ...partial, last_reason: 'peer timeout' }), 'stalled')
})

test('absent or all-false runtime is off, not stalled', () => {
  assert.equal(readinessStatus(null), 'off')
  assert.equal(readinessStatus(undefined), 'off')
  assert.equal(readinessStatus({}), 'off')
  assert.equal(readinessSummary(null), '未启用')
})
