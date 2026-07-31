// Single source of truth for turning a raw modem dBm reading into a quality
// rating and a bar count.
//
// This exists because the same reading used to be graded twice with different
// thresholds: DeviceCard rated green above -70 with 4 bars, DeviceOverviewTab
// rated green at or above -85 with 5 bars. A device sitting at -80 dBm therefore
// showed amber on the dashboard and green on its own detail page -- the operator
// had no way to tell which one to believe.
//
// The thresholds below follow the conventional LTE RSRP bands (excellent
// > -84 dBm, good -84..-102, fair -102..-111, poor below that), snapped to round
// numbers. They are stated once here so both views grade identically.

export type SignalQuality = 'excellent' | 'good' | 'fair' | 'poor' | 'unknown'

/** Total bars a full-strength reading fills. */
export const SIGNAL_BAR_COUNT = 4

// Modems report "no measurement" in several ways, and each of these has been seen
// in the wild: absent, 0, or the -999 sentinel. Treating any of them as a real
// reading would paint a dead radio as a very weak but present one.
export function hasValidSignalDbm(dbm: number | null | undefined): dbm is number {
  return typeof dbm === 'number' && Number.isFinite(dbm) && dbm !== 0 && dbm !== -999
}

export function signalQuality(dbm: number | null | undefined): SignalQuality {
  if (!hasValidSignalDbm(dbm)) return 'unknown'
  if (dbm >= -85) return 'excellent'
  if (dbm >= -100) return 'good'
  if (dbm >= -110) return 'fair'
  return 'poor'
}

/**
 * Bars to fill, 0..SIGNAL_BAR_COUNT. Zero means "no reading", which renders as an
 * empty meter and is deliberately distinct from 1 bar ("measured, and very weak").
 */
export function signalBars(dbm: number | null | undefined): number {
  switch (signalQuality(dbm)) {
    case 'excellent':
      return 4
    case 'good':
      return 3
    case 'fair':
      return 2
    case 'poor':
      return 1
    case 'unknown':
      return 0
  }
}

// Quality maps onto the semantic ramps, never onto the accent colour: signal
// strength is a measurement, and the accent is reserved for things the operator
// can act on. `fair` and `poor` share the warning/danger split rather than getting
// their own hue, so the meter stays readable at 12px.
export function signalToneClass(dbm: number | null | undefined): string {
  switch (signalQuality(dbm)) {
    case 'excellent':
      return 'text-success-600 dark:text-success-400'
    case 'good':
      return 'text-success-600 dark:text-success-400'
    case 'fair':
      return 'text-warning-600 dark:text-warning-400'
    case 'poor':
      return 'text-danger-600 dark:text-danger-400'
    case 'unknown':
      return 'text-gray-400 dark:text-gray-500'
  }
}

export function signalBarClass(dbm: number | null | undefined): string {
  switch (signalQuality(dbm)) {
    case 'excellent':
      return 'bg-success-500'
    case 'good':
      return 'bg-success-500'
    case 'fair':
      return 'bg-warning-500'
    case 'poor':
      return 'bg-danger-500'
    case 'unknown':
      return 'bg-gray-300 dark:bg-gray-600'
  }
}

/** Short Chinese label, for tooltips and screen readers. */
export function signalQualityLabel(dbm: number | null | undefined): string {
  switch (signalQuality(dbm)) {
    case 'excellent':
      return '信号强'
    case 'good':
      return '信号良好'
    case 'fair':
      return '信号一般'
    case 'poor':
      return '信号弱'
    case 'unknown':
      return '无信号读数'
  }
}
