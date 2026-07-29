package imscore

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
)

func TestServiceAdoptsOpaqueProtectedChannelAndStopClosesIt(t *testing.T) {
	owner := ipsec3gpp.NewProtectedChannelOwner()
	lease, err := owner.Reserve()
	if err != nil {
		t.Fatalf("reserve channel: %v", err)
	}
	if err := lease.Install(ipsec3gpp.PolicyInput{
		LocalIP:  net.ParseIP("2001:db8::10"),
		RemoteIP: net.ParseIP("2001:db8::20"),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg: "hmac-sha-1-96", EAlg: "aes-cbc",
			SPIc: 101, SPIs: 102, PortC: 5060, PortS: 5060,
		},
		CK: make([]byte, 16),
		IK: make([]byte, 16),
	}); err != nil {
		t.Fatalf("install channel: %v", err)
	}
	carrier := newRuntimeCarrier()
	if err := lease.OpenUDP(carrier); err != nil {
		t.Fatalf("open UDP channel: %v", err)
	}

	result := &registerResult{channel: lease}
	service := &Service{protectedChannels: owner}
	handle, err := service.adoptProtectedChannelResult(result)
	if err != nil {
		t.Fatalf("adopt result: %v", err)
	}
	if handle == nil {
		t.Fatal("Service adoption returned no channel handle")
	}
	if result.channel != nil {
		t.Fatal("register result retained an ownership-capable lease after adoption")
	}
	if _, err := service.adoptProtectedChannelResult(result); err == nil {
		t.Fatal("the same register result was adopted twice")
	}

	if err := service.Close(context.Background()); err != nil {
		t.Fatalf("Service.Close: %v", err)
	}
	if got := carrier.closeCount(); got != 1 {
		t.Fatalf("physical carrier closes = %d, want 1", got)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("close stale handle: %v", err)
	}
	if got := carrier.closeCount(); got != 1 {
		t.Fatalf("stale handle closed the carrier again: %d", got)
	}
}

func TestRegisterCandidateIsRejectedByStoppedProtectedChannelOwnerBeforeDial(t *testing.T) {
	owner := ipsec3gpp.NewProtectedChannelOwner()
	if err := owner.Close(); err != nil {
		t.Fatalf("close owner: %v", err)
	}
	network := &registerSessionTestNetwork{
		serve: func(peer net.Conn) { _ = peer.Close() },
	}
	cfg := registerSessionTestConfig()
	service := &Service{
		cfg:               cfg,
		network:           network,
		protectedChannels: owner,
	}
	attempt := service.registerRawWithCandidate(
		context.Background(),
		registerAttemptCandidate{Registrar: cfg.PCSCFAddr, Gateway: cfg.PCSCFAddr},
		"udp",
		0,
	)
	if attempt.err == nil {
		t.Fatal("stopped protected channel owner accepted a REGISTER attempt")
	}
	if network.dialCount != 0 {
		t.Fatalf("IMS network dials = %d, want 0 after owner Stop", network.dialCount)
	}
}

func TestFailedProtectedChannelAdoptionClosesForeignLease(t *testing.T) {
	serviceOwner := ipsec3gpp.NewProtectedChannelOwner()
	foreignOwner := ipsec3gpp.NewProtectedChannelOwner()
	lease, err := foreignOwner.Reserve()
	if err != nil {
		t.Fatalf("reserve foreign lease: %v", err)
	}
	if err := lease.Install(ipsec3gpp.PolicyInput{
		LocalIP:  net.ParseIP("2001:db8::10"),
		RemoteIP: net.ParseIP("2001:db8::20"),
		Mech: ipsec3gpp.SecurityMechanism{
			Alg: "hmac-sha-1-96", EAlg: "aes-cbc",
			SPIc: 201, SPIs: 202, PortC: 5060, PortS: 5060,
		},
		CK: make([]byte, 16),
		IK: make([]byte, 16),
	}); err != nil {
		t.Fatalf("install foreign lease: %v", err)
	}
	carrier := newRuntimeCarrier()
	if err := lease.OpenUDP(carrier); err != nil {
		t.Fatalf("open foreign lease: %v", err)
	}
	result := &registerResult{channel: lease}
	service := &Service{protectedChannels: serviceOwner}
	if _, err := service.adoptProtectedChannelResult(result); err == nil {
		t.Fatal("foreign lease was adopted")
	}
	if result.channel != nil {
		t.Fatal("failed result retained its lease")
	}
	if got := carrier.closeCount(); got != 1 {
		t.Fatalf("failed-result carrier closes = %d, want 1", got)
	}
	_ = serviceOwner.Close()
	_ = foreignOwner.Close()
}

func TestRegisterCandidateFailureReleasesProtectedChannelGeneration(t *testing.T) {
	network := &scriptedRegisterIMSNetwork{
		dial: func(string) (net.Conn, error) {
			return &immediateRegisterTimeoutConn{}, nil
		},
	}
	cfg := registerSessionTestConfig()
	owner := ipsec3gpp.NewProtectedChannelOwner()
	service := &Service{
		imsCfg:            IMSConfig{Transport: "udp"},
		cfg:               cfg,
		network:           network,
		protectedChannels: owner,
	}
	attempt := service.registerRawWithCandidate(
		context.Background(),
		registerAttemptCandidate{Registrar: cfg.PCSCFAddr, Gateway: cfg.PCSCFAddr},
		"udp",
		0,
	)
	if attempt.err == nil {
		t.Fatal("synthetic candidate unexpectedly succeeded")
	}
	var held []*ipsec3gpp.ProtectedChannelLease
	for i := 0; i < 256; i++ {
		lease, err := owner.Reserve()
		if err != nil {
			t.Fatalf("reservation %d after failed candidate: %v", i+1, err)
		}
		held = append(held, lease)
	}
	for _, lease := range held {
		_ = lease.Close()
	}
	_ = owner.Close()
}

func TestProtectedChannelExhaustionFailsWithoutFallback(t *testing.T) {
	network := &scriptedRegisterIMSNetwork{
		dial: func(string) (net.Conn, error) {
			return nil, errors.New("network must not be reached")
		},
	}
	cfg := registerSessionTestConfig()
	owner := ipsec3gpp.NewProtectedChannelOwner()
	service := &Service{
		imsCfg:            IMSConfig{Transport: "auto"},
		cfg:               cfg,
		network:           network,
		protectedChannels: owner,
	}
	var held []*ipsec3gpp.ProtectedChannelLease
	for len(held) < 256 {
		lease, err := owner.Reserve()
		if err != nil {
			t.Fatalf("reserve live generation %d: %v", len(held)+1, err)
		}
		held = append(held, lease)
	}
	defer func() {
		for _, lease := range held {
			_ = lease.Close()
		}
		_ = owner.Close()
	}()
	attempt := service.registerRawWithCandidate(
		context.Background(),
		registerAttemptCandidate{Registrar: cfg.PCSCFAddr, Gateway: cfg.PCSCFAddr},
		"udp",
		0,
	)
	if !errors.Is(attempt.err, errProtectedPortsExhausted) {
		t.Fatalf("attempt error = %v, want protected channel exhaustion", attempt.err)
	}
	if got := len(network.dialedTransports()); got != 0 {
		t.Fatalf("network dials = %d, want 0", got)
	}
	if shouldRetryNextRegisterTransport(0, attempt.err, 0, 2, false) {
		t.Fatal("protected channel exhaustion would retry another transport")
	}
	if shouldAdvanceRegistrarForProbeError(attempt.err, true) {
		t.Fatal("protected channel exhaustion would advance registrar candidate")
	}
}
