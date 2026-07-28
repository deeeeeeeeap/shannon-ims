//go:build linux

package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
)

type staticEPDGResolver struct {
	addresses []net.IPAddr
}

type failingEPDGResolver struct{}

func (failingEPDGResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, errors.New("synthetic resolver failure")
}

func (r staticEPDGResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), r.addresses...), nil
}

func completedSyntheticSWULease(candidate epdgCandidate, snapshot swuSnapshot) *swuSessionLease {
	ready := make(chan struct{})
	connectDone := make(chan struct{})
	joined := make(chan struct{})
	close(ready)
	close(connectDone)
	close(joined)
	return &swuSessionLease{
		candidate:   candidate,
		ready:       ready,
		readySeen:   true,
		connectDone: connectDone,
		joined:      joined,
		snapshot:    snapshot,
		localIP:     append(net.IP(nil), preferTunnelLocalIP(snapshot)...),
	}
}

func TestEstablishSWuTriesNextAddressAfterFirstCandidateTimesOut(t *testing.T) {
	instance := &Instance{lifecycleGeneration: 1}
	var attempted []int
	req := StartRequest{
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.20")},
		}},
		swuStarter: func(_ context.Context, _ StartRequest, candidate epdgCandidate, _ string) (*swuSessionLease, error) {
			attempted = append(attempted, candidate.Index)
			if candidate.Index == 1 {
				return nil, context.DeadlineExceeded
			}
			return completedSyntheticSWULease(candidate, swuSnapshot{Established: true}), nil
		},
	}

	lease, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1)
	if err != nil {
		t.Fatalf("establishSWu() error = %v", err)
	}
	if !lease.Snapshot().Established {
		t.Fatal("establishSWu() returned a non-established snapshot")
	}
	if winner := lease.Candidate(); winner.Index != 2 {
		t.Fatalf("winning candidate index = %d, want 2", winner.Index)
	}
	if want := []int{1, 2}; !reflect.DeepEqual(attempted, want) {
		t.Fatalf("attempted candidate indexes = %v, want %v", attempted, want)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("establishSWu() returned the first candidate timeout")
	}
}

func TestNormalizeEPDGCandidatesKeepsBothAddressFamiliesWithinBound(t *testing.T) {
	addresses := make([]net.IPAddr, 0, 10)
	for index := 1; index <= 9; index++ {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(fmt.Sprintf("2001:db8::%x", index))})
	}
	addresses = append(addresses, net.IPAddr{IP: net.ParseIP("192.0.2.10")})

	candidates := normalizeEPDGCandidates(addresses, 8)
	if len(candidates) != 8 {
		t.Fatalf("candidate count = %d, want 8", len(candidates))
	}
	if candidates[0].Family != "ipv6" {
		t.Fatalf("first candidate family = %q, want resolver-preferred ipv6", candidates[0].Family)
	}
	if candidates[1].Family != "ipv4" {
		t.Fatalf("second candidate family = %q, want ipv4 fallback", candidates[1].Family)
	}
}

func TestEstablishSWuReturnsTunnelIKETimeoutAfterAllCandidatesFail(t *testing.T) {
	instance := &Instance{lifecycleGeneration: 1}
	attempts := 0
	req := StartRequest{
		epdgResolver: staticEPDGResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("2001:db8::10")},
			{IP: net.ParseIP("192.0.2.20")},
		}},
		swuStarter: func(context.Context, StartRequest, epdgCandidate, string) (*swuSessionLease, error) {
			attempts++
			return nil, context.DeadlineExceeded
		},
	}

	_, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1)
	if !errors.Is(err, errTunnelIKETimeout) {
		t.Fatalf("establishSWu() error = %v, want errTunnelIKETimeout", err)
	}
	if attempts != 3 {
		t.Fatalf("candidate attempts = %d, want 3", attempts)
	}
}

func TestEstablishSWuPreservesTunnelDNSFailureClassification(t *testing.T) {
	instance := &Instance{lifecycleGeneration: 1}
	req := StartRequest{epdgResolver: failingEPDGResolver{}}

	_, err := instance.establishSWu(context.Background(), req, "epdg.test.invalid", "500", 1)
	if got := classifyTunnelFailure(err); got != "tunnel_dns_failed" {
		t.Fatalf("classifyTunnelFailure() = %q, want tunnel_dns_failed (err=%v)", got, err)
	}
}
