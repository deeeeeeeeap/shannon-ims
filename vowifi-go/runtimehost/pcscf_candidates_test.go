package runtimehost

import (
	"net"
	"testing"
)

func TestResolvePCSCFCandidatesPrefersMatchingFamily(t *testing.T) {
	local := net.ParseIP("2a03:dd00:124e:6119:9648:6f36:6f4c:a215")
	v4 := net.ParseIP("203.0.113.1")
	v6a := net.ParseIP("2a03:dd00:1f80:4860::4")
	v6b := net.ParseIP("2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646")

	got := resolvePCSCFCandidates(swuSnapshot{
		PCSCFv4: []net.IP{v4},
		PCSCFv6: []net.IP{v6a, v6b},
	}, "", local)

	want := []string{
		"[2a03:dd00:124e:6119:9648:6f36:6f4c:a215]:5060",
		"[2a03:dd00:1f80:4860::4]:5060",
		"[2a03:dd00:140b:cd45:c849:9ff6:a0c0:6646]:5060",
		"203.0.113.1:5060",
	}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestResolvePCSCFCandidatesUsesOverrideWhenIKEEmpty(t *testing.T) {
	got := resolvePCSCFCandidates(swuSnapshot{}, "[2a03:dd00:1f80:60::4]:5060", nil)
	if len(got) != 1 || got[0] != "[2a03:dd00:1f80:60::4]:5060" {
		t.Fatalf("got=%v", got)
	}
}

func TestResolvePCSCFCandidatesDedupes(t *testing.T) {
	ip := net.ParseIP("2a03:dd00:1f80:4860::4")
	got := resolvePCSCFCandidates(swuSnapshot{
		PCSCFv6: []net.IP{ip, ip},
	}, "", ip)
	if len(got) != 1 {
		t.Fatalf("got=%v", got)
	}
}