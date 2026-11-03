package voiceclient

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/emiago/sipgo/sip"
)

func TestSendSMSWaitsForFinalSuccess(t *testing.T) {
	for _, code := range []int{200, 202} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			conn := newScriptedSMSConn()
			client := newStatusReportTestClient(t, conn, nil)
			defer client.Close(context.Background())
			serverDone := make(chan error, 1)
			go func() {
				payload, err := conn.nextClientWrite()
				if err != nil {
					serverDone <- err
					return
				}
				message, err := sip.NewParser().ParseSIP(payload)
				if err != nil {
					serverDone <- err
					return
				}
				req := message.(*sip.Request)
				conn.queueInbound([]byte(sip.NewResponseFromRequest(req, 100, "Trying", nil).String()))
				conn.queueInbound([]byte(sip.NewResponseFromRequest(req, code, "Success", nil).String()))
				serverDone <- nil
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			outcome, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "fixture", []messaging.SMSPart{{RPMR: 1, Body: []byte{0, 1}}})
			if err != nil {
				t.Fatalf("valid final response rejected: %v", err)
			}
			if outcome.DeliveryState != "pending" {
				t.Fatal("SIP success must not claim recipient delivery")
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSecureSMSWriteHonorsCancellation(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	client, err := AttachSecureMessaging(context.Background(), Config{
		LocalIP: net.ParseIP("192.0.2.1"), LocalPort: 5062, PCSCFAddr: "192.0.2.2:5060",
		PrivateID: "fixture@example.invalid", PublicURI: "sip:fixture@example.invalid", HomeDomain: "example.invalid", SMSC: "sip:smsc@example.invalid",
	}, local)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := client.SendSMS(ctx, "sip:peer@example.invalid", "fixture", []messaging.SMSPart{{Body: []byte{0, 1}}})
		done <- err
	}()
	// No peer reader: the write cannot finish on its own.
	time.AfterFunc(20*time.Millisecond, cancel)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled send succeeded")
		}
	case <-time.After(time.Second):
		_ = remote.Close()
		<-done
		t.Fatal("canceled write blocked the messaging channel")
	}
}

func TestSendSMSUsesServiceCentreFromCurrentSIMRead(t *testing.T) {
	conn := newScriptedSMSConn()
	client := newStatusReportTestClient(t, conn, nil)
	defer client.Close(context.Background())
	const currentSC = "sip:current-smsc@ims.example.invalid"
	serverDone := make(chan error, 1)
	go func() {
		payload, err := conn.nextClientWrite()
		if err != nil {
			serverDone <- err
			return
		}
		message, err := sip.NewParser().ParseSIP(payload)
		if err != nil {
			serverDone <- err
			return
		}
		req := message.(*sip.Request)
		if req.Recipient.String() != currentSC {
			serverDone <- fmt.Errorf("request used stale startup SMSC")
			return
		}
		conn.queueInbound([]byte(sip.NewResponseFromRequest(req, 202, "Accepted", nil).String()))
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := client.SendSMS(ctx, "sip:peer@ims.example.invalid", "fixture", []messaging.SMSPart{{RPMR: 1, Body: []byte{0, 1}, ServiceCentre: currentSC}})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
