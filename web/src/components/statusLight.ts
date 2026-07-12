export type StatusLightTone = 'success' | 'warning' | 'danger' | 'neutral'
export type StatusLightSize = 'sm' | 'md'

export function statusLightToneClass(tone: StatusLightTone) {
  switch (tone) {
    case 'success':
      return 'bg-green-500'
    case 'warning':
      return 'bg-amber-500'
    case 'danger':
      return 'bg-red-500'
    case 'neutral':
      return 'bg-gray-400'
  }
}

export function statusLightSizeClass(size: StatusLightSize) {
  return size === 'md' ? 'w-1.5 h-1.5' : 'w-2 h-2'
}

export function statusLightAnimatedClass(animated = true) {
  return animated ? 'animate-pulse' : ''
}
