package voiceclient

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/emiago/sipgo/sip"
)

func TestSecureSMSUsesTimerFWithoutRetransmitting(t *testing.T) {
	previous := sip.Timer_F
	sip.Timer_F = 20 * time.Millisecond
	t.Cleanup(func() { sip.Timer_F = previous })
	conn := newScriptedSMSConn()
	client := newStatusReportTestClient(t, conn, nil)
	defer client.Close(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SendSMS(context.Background(), "fixture", "fixture", []messaging.SMSPart{{Body: []byte{0, 1}}})
		done <- err
	}()
	if _, err := conn.nextClientWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("send error = %v, want deadline", err)
		}
	case <-time.After(time.Second):
		_ = conn.Close()
		<-done
		t.Fatal("silent gateway has no transaction deadline")
	}
	select {
	case <-conn.clientWrites:
		t.Fatal("timed out SMS was automatically resubmitted")
	default:
	}
}

func TestSecureSMSHonorsEarlierCallerDeadline(t *testing.T) {
	conn := newScriptedSMSConn()
	client := newStatusReportTestClient(t, conn, nil)
	defer client.Close(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.SendSMS(ctx, "fixture", "fixture", []messaging.SMSPart{{Body: []byte{0, 1}}})
		done <- err
	}()
	if _, err := conn.nextClientWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("send error = %v, want caller deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller deadline was ignored")
	}
}

func TestSecureStreamLegacyServerReplyStopsAtTimerF(t *testing.T) {
	previous := sip.Timer_F
	sip.Timer_F = 20 * time.Millisecond
	t.Cleanup(func() { sip.Timer_F = previous })
	local, peer := net.Pipe()
	defer peer.Close()
	server, serverPeer := net.Pipe()
	defer serverPeer.Close()
	conn := newSecureMessagingTestDualFlowConn(local, server)
	client, err := AttachSecureStreamMessaging(context.Background(), Config{
		LocalIP: net.ParseIP("192.0.2.10"), LocalPort: 5062,
		PCSCFAddr: "192.0.2.20:5060", PrivateID: "fixture@example.invalid",
		PublicURI: "sip:fixture@example.invalid", HomeDomain: "example.invalid",
	}, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	request := []byte("OPTIONS sip:fixture@example.invalid SIP/2.0\r\nVia: SIP/2.0/TCP 192.0.2.20;branch=z9hG4bK-fixture\r\nFrom: <sip:gateway@example.invalid>;tag=fixture\r\nTo: <sip:fixture@example.invalid>\r\nCall-ID: fixture\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n")
	if _, err := serverPeer.Write(request); err != nil {
		t.Fatal(err)
	}
	// The peer deliberately never reads the response on the server flow.
	select {
	case <-client.Done():
	case <-time.After(time.Second):
		_ = conn.Close()
		t.Fatal("legacy server-flow reply was not bounded by Timer F")
	}
}
