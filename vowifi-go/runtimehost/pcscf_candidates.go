package runtimehost

import (
	"net"
	"strings"
)

const defaultPCSCFPort = "5060"

// resolvePCSCFCandidates collects registrar endpoints for IMS REGISTER probing.
// Author v1.5.5 discoverRegistrarViaIMSNetwork uses the UE inner IPv6 as the
// primary registrar, then falls back to IKE/ePDG P-CSCF addresses.
func resolvePCSCFCandidates(snapshot swuSnapshot, override string, localIP net.IP) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 1+len(snapshot.PCSCFv4)+len(snapshot.PCSCFv6))

	if localIP != nil && localIP.To4() == nil {
		if addr := formatPCSCFAddr(localIP); addr != "" {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}

	groups := [][]net.IP{snapshot.PCSCFv4, snapshot.PCSCFv6}
	if localIP != nil && localIP.To4() == nil {
		groups = [][]net.IP{snapshot.PCSCFv6, snapshot.PCSCFv4}
	}
	for _, group := range groups {
		for _, ip := range group {
			if ip == nil {
				continue
			}
			addr := formatPCSCFAddr(ip)
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		if v := strings.TrimSpace(override); v != "" {
			return []string{v}
		}
	}
	return out
}

func resolvePCSCFAddr(snapshot swuSnapshot, override string, localIP net.IP) string {
	candidates := resolvePCSCFCandidates(snapshot, override, localIP)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func formatPCSCFAddr(ip net.IP) string {
	return net.JoinHostPort(ip.String(), defaultPCSCFPort)
}