package imscore

import (
	"net"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
)

const (
	registrarSourceIMSNetwork = "ims_network"
	registrarSourceConfigured = "configured"
)

// discoverRegistrar picks the logical SIP registrar from IKE/ePDG candidates.
// Author v1.1.2 prefers the UE inner address when its family matches the tunnel.
func discoverRegistrar(cfg Config, localIP net.IP) (registrar string, source string) {
	candidates := registrarCandidates(cfg)
	primary, fallback := splitRegistrarCandidates(candidates, localIP)
	if v := pickRegistrar(primary, localIP); v != "" {
		return v, registrarSourceIMSNetwork
	}
	if v := pickRegistrar(fallback, localIP); v != "" {
		return v, registrarSourceIMSNetwork
	}
	if v := strings.TrimSpace(cfg.PCSCFAddr); v != "" {
		return v, registrarSourceConfigured
	}
	return "", registrarSourceConfigured
}

func pickRegistrar(candidates []string, localIP net.IP) string {
	if localIP != nil {
		for _, candidate := range candidates {
			if registrarHostEqualsLocalIP(candidate, localIP) {
				return candidate
			}
		}
	}
	for _, candidate := range candidates {
		if registrarSpecMatchesFamily(candidate, localIP) {
			return candidate
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

func registrarSpecMatchesFamily(addr string, localIP net.IP) bool {
	if localIP == nil {
		return true
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	localV4 := localIP.To4() != nil
	candidateV4 := ip.To4() != nil
	return localV4 == candidateV4
}

func splitRegistrarCandidates(candidates []string, localIP net.IP) (primary []string, fallback []string) {
	for _, candidate := range candidates {
		if registrarSpecMatchesFamily(candidate, localIP) {
			primary = append(primary, candidate)
			continue
		}
		fallback = append(fallback, candidate)
	}
	return primary, fallback
}

func discoverRegistrarViaIMSNetwork(candidates []string, localIP net.IP, override string) (registrar string, source string, expanded []string) {
	expanded = expandRegistrarCandidatesViaIMSNetwork(candidates, localIP)
	if len(expanded) == 0 {
		if v := strings.TrimSpace(override); v != "" {
			expanded = []string{v}
		}
	}
	registrar = pickRegistrar(expanded, localIP)
	if registrar != "" {
		return registrar, registrarSourceIMSNetwork, expanded
	}
	if v := strings.TrimSpace(override); v != "" {
		return v, registrarSourceConfigured, expanded
	}
	return "", registrarSourceConfigured, expanded
}

func expandRegistrarCandidatesViaIMSNetwork(candidates []string, localIP net.IP) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(candidates)+1)

	appendCandidate := func(addr string) {
		v := strings.TrimSpace(addr)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	if localIP != nil {
		if addr := formatRegistrarAddr(localIP); addr != "" {
			appendCandidate(addr)
		}
	}

	primary, fallback := splitRegistrarCandidates(dedupeRegistrarAddrs(candidates), localIP)
	for _, addr := range primary {
		appendCandidate(addr)
	}
	for _, addr := range fallback {
		appendCandidate(addr)
	}
	return out
}

func formatRegistrarAddr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), defaultRegistrarPort())
}

func defaultRegistrarPort() string {
	return "5060"
}

func reportRegistrarDiscoveryProgress(traceID, deviceID, registrar, source string, candidateCount int) {
	logger.Info("IMS registrar discovery",
		logger.String("trace_id", strings.TrimSpace(traceID)),
		logger.String("device_id", strings.TrimSpace(deviceID)),
		logger.String("registrar", strings.TrimSpace(registrar)),
		logger.String("registrar_source", strings.TrimSpace(source)),
		logger.Int("registrar_candidates", candidateCount))
}