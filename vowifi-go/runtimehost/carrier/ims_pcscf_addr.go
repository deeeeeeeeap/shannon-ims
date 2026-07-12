package carrier

import "strings"

// ResolveIMSPcscfAddr returns a carrier preset P-CSCF override ("host:port") when set.
func ResolveIMSPcscfAddr(mcc, mnc string) string {
	preset, ok := lookup(mcc, mnc)
	if !ok {
		return ""
	}
	return strings.TrimSpace(preset.IMSPcscfAddr)
}