package imscore

import (
	"net"
	"testing"
)

func TestEffectiveTransportAddrPrefersExplicitOverride(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1106:5794:20a6:6ac0:4821:850e")
	cfg := Config{
		LocalIP:            local,
		PCSCFAddr:          "[2a03:dd00:1106:5794:20a6:6ac0:4821:850e]:5060",
		TransportPCSCFAddr: "[2a03:dd00:1f81:3010::4]:5060",
		RegistrarCandidates: []string{
			"[2a03:dd00:1106:5794:20a6:6ac0:4821:850e]:5060",
			"[2a03:dd00:1f81:3010::4]:5060",
		},
	}
	if got := effectiveTransportAddr(cfg); got != "[2a03:dd00:1f81:3010::4]:5060" {
		t.Fatalf("transport=%q", got)
	}
	ip := effectiveIPSecRemoteIP(cfg)
	if ip == nil || ip.String() != "2a03:dd00:1f81:3010::4" {
		t.Fatalf("ipsec remote=%v", ip)
	}
}

func TestEffectiveIPSecRemoteIPFromRegistrarWhenNoOverride(t *testing.T) {
	cfg := Config{PCSCFAddr: "[2a03:dd00:1f80:4860::4]:5060"}
	ip := effectiveIPSecRemoteIP(cfg)
	if ip == nil || ip.String() != "2a03:dd00:1f80:4860::4" {
		t.Fatalf("ipsec remote=%v", ip)
	}
}

func TestEffectiveIPSecRemoteIPPrefersCurrentAttemptTransportOverOtherCandidates(t *testing.T) {
	cfg := Config{
		PCSCFAddr:          "[2001:db8:10::4]:5060",
		TransportPCSCFAddr: "[2001:db8:20::4]:5060",
		RegistrarCandidates: []string{
			"[2a03:dd00:1f80:60::4]:5060",
			"[2001:db8:20::4]:5060",
		},
	}
	ip := effectiveIPSecRemoteIP(cfg)
	if ip == nil || ip.String() != "2001:db8:20::4" {
		t.Fatalf("ipsec remote=%v, want current attempt transport", ip)
	}
}

func TestEffectiveRouteAddrUsesGatewayForLocalRegistrar(t *testing.T) {
	local := net.ParseIP("2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646")
	cfg := Config{
		LocalIP:            local,
		PCSCFAddr:          "[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060",
		TransportPCSCFAddr: "[2a03:dd00:1f80:60::4]:5060",
	}
	if got := effectiveRouteAddr(cfg); got != "[2a03:dd00:1f80:60::4]:5060" {
		t.Fatalf("route=%q", got)
	}
}

func TestEffectiveIPSecGatewayUsesIKECandidateForLocalRegistrar(t *testing.T) {
	local := net.ParseIP("2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646")
	cfg := Config{
		LocalIP:   local,
		PCSCFAddr: "[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060",
		RegistrarCandidates: []string{
			"[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060",
			"[2a03:dd00:1f80:60::4]:5060",
		},
	}
	if got := effectiveTransportAddr(cfg); got != "[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060" {
		t.Fatalf("transport=%q", got)
	}
	if got := effectiveIPSecGatewayAddr(cfg); got != "[2a03:dd00:1f80:60::4]:5060" {
		t.Fatalf("ipsec gateway=%q", got)
	}
	ip := effectiveIPSecRemoteIP(cfg)
	if ip == nil || ip.String() != "2a03:dd00:1f80:60::4" {
		t.Fatalf("ipsec remote=%v", ip)
	}
	_ = net.ParseIP
}
