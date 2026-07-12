package imscore

import (
	"net"
	"testing"
)

func TestSplitRegistrarCandidatesByFamily(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1381:7dce:fb36:ef7b:d917:548b")
	primary, fallback := splitRegistrarCandidates([]string{
		"[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060",
		"[2a03:dd00:1f80:4860::4]:5060",
		"10.0.0.1:5060",
	}, local)
	if len(primary) != 2 {
		t.Fatalf("primary=%v", primary)
	}
	if len(fallback) != 1 || fallback[0] != "10.0.0.1:5060" {
		t.Fatalf("fallback=%v", fallback)
	}
}

func TestDiscoverRegistrarPrefersLocalIPv6(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1381:7dce:fb36:ef7b:d917:548b")
	got, source := discoverRegistrar(Config{
		LocalIP: local,
		RegistrarCandidates: []string{
			"[2a03:dd00:1f80:4860::4]:5060",
			"[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060",
		},
	}, local)
	want := "[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060"
	if got != want || source != registrarSourceIMSNetwork {
		t.Fatalf("got=%q source=%q", got, source)
	}
}

func TestExpandRegistrarCandidatesViaIMSNetworkLocalFirst(t *testing.T) {
	local := net.ParseIP("2a03:dd00:1381:7dce:fb36:ef7b:d917:548b")
	got := expandRegistrarCandidatesViaIMSNetwork([]string{
		"[2a03:dd00:1f80:4860::4]:5060",
	}, local)
	if len(got) != 2 {
		t.Fatalf("got=%v", got)
	}
	if got[0] != "[2a03:dd00:1381:7dce:fb36:ef7b:d917:548b]:5060" {
		t.Fatalf("first=%q", got[0])
	}
}