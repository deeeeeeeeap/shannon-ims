export function isWwanQmiControlPath(path: string | null | undefined): boolean {
  const value = String(path || '').trim()
  if (!value) return false
  const basename = value.replace(/\\/g, '/').split('/').filter(Boolean).pop() || value
  return /^wwan\d+qmi\d+$/.test(basename)
}
