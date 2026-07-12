export const upstreamProxyIPv6AddressHint = 'IPv6 地址请使用 [IPv6]:port，例如 [2001:db8::1]:1080'

export function upstreamProxyAddressWarning(addr: string): string {
  const value = String(addr || '').trim()
  if (!value || value.startsWith('[')) {
    return ''
  }
  if ((value.match(/:/g) || []).length > 1) {
    return upstreamProxyIPv6AddressHint
  }
  return ''
}
