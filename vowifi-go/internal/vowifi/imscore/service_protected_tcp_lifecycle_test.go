package imscore

import (
	"context"
	"net"
	"testing"
)

func TestServiceAdoptsOpaqueProtectedTCPChannelAndJoinsItOnClose(t *testing.T) {
	fixture := newProtectedChannelTCPFixture(t)
	cfg := syntheticProtectedRegisterConfig()
	cfg.LocalIP = net.ParseIP("2001:db8::10")
	result := &registerResult{
		channel:      fixture.lease,
		verifyHeader: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc",
	}
	service := &Service{cfg: cfg, protectedChannels: fixture.owner}
	handle, err := service.adoptProtectedChannelResult(result)
	if err != nil {
		t.Fatalf("adopt protected channel: %v", err)
	}
	if result.channel != nil {
		t.Fatal("register result retained the lease after Service adoption")
	}
	if handle.PacketMode() {
		t.Fatal("adopted TCP channel reports packet mode")
	}
	if err := service.attachMessaging(context.Background(), cfg.PCSCFAddr, result, handle); err != nil {
		t.Fatalf("attach messaging: %v", err)
	}
	if !service.MessagingReady() {
		t.Fatal("protected TCP service did not attach messaging to the opaque channel")
	}

	if err := service.Close(context.Background()); err != nil {
		t.Fatalf("Service.Close: %v", err)
	}
	if got := fixture.clientCarrier.closeCount.Load(); got != 1 {
		t.Fatalf("physical carrier closes = %d, want 1", got)
	}
	if _, err := handle.Write([]byte("stale")); err == nil {
		t.Fatal("stale channel handle remained writable after Service.Close")
	}
}
