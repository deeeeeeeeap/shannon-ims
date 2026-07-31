import type { VoWiFiRuntimeState } from '../types/api'

// VoWiFi readiness is an ORDERED chain, not a set of independent flags:
//
//   SIM -> Access -> Tunnel -> IMS -> SMS
//
// Each stage depends on the one before it, so "stalled at Tunnel" and "stalled at
// SMS" are very different situations -- the first means the ePDG connection never
// came up, the second means registration succeeded and only messaging is missing.
//
// The previous summary lost that: it graded with `all.some(Boolean)` and listed
// unready stage names unordered, so both cases rendered as the same "partial".
// This module keeps the order and reports the FIRST stage that is not ready, which
// is the one an operator has to act on.
//
// IMS and SMS stay separate stages on purpose: the architecture treats IMSReady and
// SMSReady as distinct states, and a registered device with no messaging capability
// is a real and diagnostically meaningful condition.

export type ReadinessStageKey = 'SIM' | 'Access' | 'Tunnel' | 'IMS' | 'SMS'

export type ReadinessStage = {
  key: ReadinessStageKey
  /** Chinese label for tooltips and accessible text. */
  label: string
  ready: boolean
  /**
   * True for the first not-ready stage. Everything after it is blocked rather than
   * independently broken, so the UI should draw attention here and not to the tail.
   */
  blocking: boolean
}

/** Chain order is load-bearing; do not reorder. */
const STAGE_LABELS: Array<{ key: ReadinessStageKey; label: string }> = [
  { key: 'SIM', label: 'SIM 就绪' },
  { key: 'Access', label: '接入就绪' },
  { key: 'Tunnel', label: '隧道就绪' },
  { key: 'IMS', label: 'IMS 注册' },
  { key: 'SMS', label: '短信就绪' },
]

function stageFlags(rt: VoWiFiRuntimeState | null | undefined): boolean[] {
  return [
    !!rt?.sim_ready,
    !!rt?.access_ready,
    !!rt?.tunnel_ready,
    !!rt?.ims_ready,
    !!rt?.sms_ready,
  ]
}

export function readinessStages(rt: VoWiFiRuntimeState | null | undefined): ReadinessStage[] {
  const flags = stageFlags(rt)
  const firstNotReady = flags.indexOf(false)
  return STAGE_LABELS.map((stage, i) => ({
    key: stage.key,
    label: stage.label,
    ready: flags[i],
    blocking: i === firstNotReady,
  }))
}

export type VowifiReadinessStatus = 'ready' | 'progressing' | 'stalled' | 'off'

/**
 * `off`         - no runtime at all; VoWiFi was never started.
 * `ready`       - every stage up to and including SMS is ready.
 * `progressing` - some stages are up and the runtime reported no error.
 * `stalled`     - some stages are up but the runtime carries an error/reason.
 *
 * `progressing` and `stalled` are separated because they call for different
 * operator responses: one is worth waiting out, the other is not. The old
 * three-value version collapsed them into `partial`.
 */
export function readinessStatus(rt: VoWiFiRuntimeState | null | undefined): VowifiReadinessStatus {
  if (!rt) return 'off'
  const flags = stageFlags(rt)
  if (flags.every(Boolean)) return 'ready'
  if (!flags.some(Boolean)) return 'off'
  return hasRuntimeFault(rt) ? 'stalled' : 'progressing'
}

export function hasRuntimeFault(rt: VoWiFiRuntimeState | null | undefined): boolean {
  return !!(rt?.last_error_class || rt?.last_reason)
}

/** The stage the operator should look at, or null when fully ready / never started. */
export function blockingStage(rt: VoWiFiRuntimeState | null | undefined): ReadinessStage | null {
  if (!rt) return null
  return readinessStages(rt).find(s => s.blocking) ?? null
}

/**
 * One-line summary naming the blocking stage, e.g. "隧道就绪 未完成（3/5）".
 * Naming the stage is the point: "部分就绪" told the operator nothing actionable.
 */
export function readinessSummary(rt: VoWiFiRuntimeState | null | undefined): string {
  const status = readinessStatus(rt)
  if (status === 'off') return '未启用'
  if (status === 'ready') return '全部就绪'
  const stages = readinessStages(rt)
  const readyCount = stages.filter(s => s.ready).length
  const blocking = stages.find(s => s.blocking)
  if (!blocking) return '全部就绪'
  const verb = status === 'stalled' ? '受阻于' : '进行中'
  return `${verb} ${blocking.label}（${readyCount}/${stages.length}）`
}
