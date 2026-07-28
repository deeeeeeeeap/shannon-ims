package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/emiago/sipgo/sip"
)

func TestServiceSendSMSUsesTransferredProtectedTCPClientFlow(t *testing.T) {
	cfg, state, _, allocator := runtimeTestStateWithAllocator(t)
	cfg.SMSC = "+15550102030"
	dialer := &countingCarrierDialer{}
	runtime, err := startProtectedTCPRuntime(context.Background(), cfg, dialer, *state)
	if err != nil {
		t.Fatalf("startProtectedTCPRuntime: %v", err)
	}
	runtime.BindPortRelease(allocator, state.generation)
	owned, ok := runtime.TakeOwnership()
	if !ok {
		t.Fatal("runtime ownership unavailable")
	}
	client, peer := net.Pipe()
	defer peer.Close()
	result := &registerResult{
		protectedTCP:        owned,
		protectedClientConn: client,
		ipsecPolicy:         state.ipsecPolicy,
		transport:           state.transport,
		verifyHeader:        "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc",
	}
	service := &Service{cfg: cfg, protectedRuntimes: newProtectedRuntimeHolder()}
	if err := service.adoptProtectedTCPResult(result); err != nil {
		t.Fatalf("adoptProtectedTCPResult: %v", err)
	}
	if err := service.attachMessaging(context.Background(), cfg.PCSCFAddr, result); err != nil {
		t.Fatalf("attachMessaging: %v", err)
	}
	defer service.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		request, err := readProtectedMessagingTestRequest(peer)
		if err != nil {
			serverDone <- err
			return
		}
		via := request.GetHeader("Via")
		contact := request.GetHeader("Contact")
		if via == nil || !strings.Contains(strings.ToUpper(via.Value()), "SIP/2.0/TCP") {
			serverDone <- fmt.Errorf("MESSAGE did not use TCP Via")
			return
		}
		if contact == nil || !strings.Contains(strings.ToLower(contact.Value()), fmt.Sprintf(":%d;transport=tcp", state.ipsecPolicy.FlowS.LocalPort)) {
			serverDone <- fmt.Errorf("MESSAGE Contact did not use protected server port")
			return
		}
		response := sip.NewResponseFromRequest(request, 202, "Accepted", nil)
		_, err = peer.Write([]byte(response.String()))
		serverDone <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	outcome, err := service.SendSMS(ctx, "sip:safe.invalid", "synthetic", []messaging.SMSPart{{RPMR: 1, Body: []byte{0x01}}})
	if err != nil {
		t.Fatalf("Service.SendSMS: %v", err)
	}
	if outcome.PartsTotal != 1 {
		t.Fatalf("PartsTotal = %d, want 1", outcome.PartsTotal)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("raw ESP carrier dials = %d, want 1", got)
	}
}

func readProtectedMessagingTestRequest(conn net.Conn) (*sip.Request, error) {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return nil, err
	}
	framer := newSIPStreamFramer(defaultSIPFramerLimits())
	buf := make([]byte, streamReadChunkLen)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			frames, frameErr := framer.Push(buf[:n])
			if frameErr != nil {
				return nil, frameErr
			}
			if len(frames) > 0 {
				message, parseErr := sip.NewParser().ParseSIP(frames[0])
				if parseErr != nil {
					return nil, parseErr
				}
				request, ok := message.(*sip.Request)
				if !ok {
					return nil, fmt.Errorf("expected SIP request")
				}
				return request, nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
}
