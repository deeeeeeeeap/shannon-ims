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

func TestServiceSendSMSUsesAdoptedProtectedTCPChannel(t *testing.T) {
	fixture := newProtectedChannelTCPFixture(t)
	cfg := syntheticProtectedRegisterConfig()
	cfg.LocalIP = net.ParseIP("2001:db8::10")
	cfg.SMSC = "+15550102030"
	result := &registerResult{
		channel:      fixture.lease,
		verifyHeader: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc",
	}
	service := &Service{cfg: cfg, protectedChannels: fixture.owner}
	handle, err := service.adoptProtectedChannelResult(result)
	if err != nil {
		t.Fatalf("adopt protected channel: %v", err)
	}
	if err := service.attachMessaging(context.Background(), cfg.PCSCFAddr, result, handle); err != nil {
		t.Fatalf("attachMessaging: %v", err)
	}
	defer service.Close(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		request, err := readProtectedMessagingTestRequest(fixture.peer)
		if err != nil {
			serverDone <- err
			return
		}
		via := request.GetHeader("Via")
		if via == nil || !strings.Contains(strings.ToUpper(via.Value()), "SIP/2.0/TCP") {
			serverDone <- fmt.Errorf("MESSAGE did not use TCP Via")
			return
		}
		if contact := request.GetHeader("Contact"); contact != nil {
			serverDone <- fmt.Errorf("MESSAGE unexpectedly included Contact")
			return
		}
		response := sip.NewResponseFromRequest(request, 202, "Accepted", nil)
		_, err = fixture.peer.Write([]byte(response.String()))
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
