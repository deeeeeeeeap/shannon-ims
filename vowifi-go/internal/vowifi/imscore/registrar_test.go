package imscore

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestDedupeRegistrarAddrs(t *testing.T) {
	got := dedupeRegistrarAddrs([]string{
		"[2a03:dd00:1f80:4860::4]:5060",
		" [2a03:dd00:1f80:4860::4]:5060 ",
		"[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060",
	})
	if len(got) != 2 {
		t.Fatalf("got=%v", got)
	}
}

func TestShouldAdvanceRegistrarForNextRetry(t *testing.T) {
	cases := []struct {
		status int
		reason string
		more   bool
		want   bool
	}{
		{sip.StatusForbidden, "Service not allowed in this location", true, true},
		{sip.StatusForbidden, "Forbidden", true, true},
		{sip.StatusUnauthorized, "", true, false},
		{sip.StatusProxyAuthRequired, "", true, false},
		{sip.StatusForbidden, "Forbidden", false, false},
		{sip.StatusServiceUnavailable, "", true, true},
	}
	for _, tc := range cases {
		if got := shouldAdvanceRegistrarForNextRetry(tc.status, tc.reason, tc.more); got != tc.want {
			t.Fatalf("status=%d more=%v got=%v want=%v", tc.status, tc.more, got, tc.want)
		}
	}
}

func TestShouldAdvanceRegistrarForProbeError(t *testing.T) {
	if !shouldAdvanceRegistrarForProbeError(context.DeadlineExceeded, true) {
		t.Fatal("expected deadline to advance")
	}
	if shouldAdvanceRegistrarForProbeError(context.DeadlineExceeded, false) {
		t.Fatal("expected no advance without more candidates")
	}
	if !shouldAdvanceRegistrarForProbeError(fmt.Errorf("transaction ended: context deadline exceeded"), true) {
		t.Fatal("expected wrapped deadline to advance")
	}
}

func TestExpandRegistrarCandidatesLocalUsesGatewayTCP(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1381:7dce:fb36:ef7b:d917:548b")
	got := expandRegistrarCandidates(Config{
		LocalIP: local,
		RegistrarCandidates: []string{
			"[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060",
			"[2a03:dd00:1f81:3010::4]:5060",
			"[2a03:dd00:1f80:4860::4]:5060",
		},
	})
	if len(got) != 4 {
		t.Fatalf("len=%d got=%v", len(got), got)
	}
	if got[0].Registrar != "[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060" {
		t.Fatalf("registrar=%q", got[0].Registrar)
	}
	if got[0].Transport != "[2a03:dd00:1f80:4860::4]:5060" {
		t.Fatalf("transport=%q", got[0].Transport)
	}
	if got[1].Transport != "[2a03:dd00:1f81:3010::4]:5060" {
		t.Fatalf("fallback transport=%q", got[1].Transport)
	}
}

func TestPickIKEGatewayCandidatePrefers1f80(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1381:7dce:fb36:ef7b:d917:548b")
	got := pickIKEGatewayCandidate([]string{
		"[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060",
		"[2a03:dd00:1f81:3010::4]:5060",
		"[2a03:dd00:1f80:4860::4]:5060",
	}, local)
	if got != "[2a03:dd00:1f80:4860::4]:5060" {
		t.Fatalf("gateway=%q", got)
	}
}

func TestRegistrarCandidatesFallbackToPCSCFAddr(t *testing.T) {
	got := registrarCandidates(Config{PCSCFAddr: "[2a03:dd00:1f80:4860::4]:5060"})
	if len(got) != 1 || got[0] != "[2a03:dd00:1f80:4860::4]:5060" {
		t.Fatalf("got=%v", got)
	}
}