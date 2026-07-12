import type { EsimChipInfo } from '../types/api'

export function pickNextDownloadAid(chipInfo: EsimChipInfo | null, currentAidHex: string): string {
  const eids = chipInfo?.eids || []
  if (eids.length === 0) return ''
  if (currentAidHex && eids.some((item) => item.aid === currentAidHex)) {
    return currentAidHex
  }
  return eids[0]?.aid || ''
}
