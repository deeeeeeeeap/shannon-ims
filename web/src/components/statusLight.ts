export type StatusLightTone = 'success' | 'warning' | 'danger' | 'neutral'
export type StatusLightSize = 'sm' | 'md'

export function statusLightToneClass(tone: StatusLightTone) {
  switch (tone) {
    case 'success':
      return 'bg-success-500'
    case 'warning':
      return 'bg-warning-500'
    case 'danger':
      return 'bg-danger-500'
    case 'neutral':
      return 'bg-gray-400'
  }
}

// The two sizes were inverted since the initial release: 'md' returned w-1.5
// (6px) and 'sm' returned w-2 (8px), so asking for the larger dot produced the
// smaller one. DeviceCard passes size="md" for its prominent per-device light and
// was getting the 6px dot.
export function statusLightSizeClass(size: StatusLightSize) {
  return size === 'md' ? 'w-2.5 h-2.5' : 'w-1.5 h-1.5'
}

export function statusLightAnimatedClass(animated = true) {
  return animated ? 'animate-pulse' : ''
}
