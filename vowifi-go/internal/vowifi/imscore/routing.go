package imscore

import (
	"net"
	"strings"
)

func effectiveTransportAddr(cfg Config) string {
	if v := strings.TrimSpace(cfg.TransportPCSCFAddr); v != "" {
		return v
	}
	return strings.TrimSpace(cfg.PCSCFAddr)
}

// effectiveRouteAddr matches author imscore: when the logical registrar is the
// UE inner IPv6 but TCP targets the IKE gateway, Route uses the gateway.
func effectiveRouteAddr(cfg Config) string {
	transport := effectiveTransportAddr(cfg)
	registrar := strings.TrimSpace(cfg.PCSCFAddr)
	if transport != "" && registrar != "" && transport != registrar {
		return transport
	}
	return registrar
}

func effectiveIPSecGatewayAddr(cfg Config) string {
	if currentAttempt := strings.TrimSpace(cfg.TransportPCSCFAddr); currentAttempt != "" {
		return currentAttempt
	}
	if gateway := pickIKEGatewayCandidate(registrarCandidates(cfg), cfg.LocalIP); gateway != "" {
		return gateway
	}
	return effectiveTransportAddr(cfg)
}

func effectiveIPSecRemoteIP(cfg Config) net.IP {
	addr := effectiveIPSecGatewayAddr(cfg)
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}
