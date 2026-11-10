package swu

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"go.uber.org/zap"
)

// When the egress path changes under an established IKE SA (a proxy relay was
// re-established, so the ePDG now sees a new source address) the session must
// send an authenticated request at once: that is what makes the peer follow
// the new address. Keepalives are unauthenticated and do not.
func TestPathChangedEventSendsAuthenticatedProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		mu        sync.Mutex
		session   *Session
		transport *initTestTransport
		reported  bool
		authID    uint32
		probe     []byte
	)
	transport = newInitTestTransport(func(request []byte) {
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		switch header.ExchangeType {
		case ikev2.IKE_SA_INIT:
			transport.ikeCh <- syntheticSuccessfulIKESAInitResponse(t, request, 0x1112131415161718)
		case ikev2.IKE_AUTH:
			// The SA keys exist from here on. IKE_AUTH stays unanswered; the
			// transport reports a path change instead.
			mu.Lock()
			first := !reported
			reported = true
			authID = header.MessageID
			mu.Unlock()
			if first {
				transport.netCh <- ipsec.NetEvent{Type: ipsec.EventPathChanged, Reason: "relay re-associated"}
			}
		case ikev2.INFORMATIONAL:
			mu.Lock()
			probe = request
			mu.Unlock()
			cancel()
		}
	})
	transport.netCh = make(chan ipsec.NetEvent, 1)

	session = NewSession(&Config{
		LocalAddr:    "192.0.2.10",
		EpDGAddr:     "192.0.2.20",
		LocalPort:    45000,
		EpDGPort:     500,
		APN:          "ims.test.invalid",
		MCC:          "001",
		MNC:          "01",
		FastReauthID: "synthetic-test-id",
		SIM:          authInitialTestSIM{},
		TransportFactory: func(string, string) (Transport, error) {
			return transport, nil
		},
	}, zap.NewNop())

	err := session.Connect(ctx)

	mu.Lock()
	defer mu.Unlock()
	if probe == nil {
		t.Fatalf("no INFORMATIONAL request followed the path change (Connect returned %v)", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect returned %v, want the test's cancellation", err)
	}
	header, err := ikev2.DecodeHeader(probe)
	if err != nil {
		t.Fatalf("decode probe header: %v", err)
	}
	if header.Flags&ikev2.FlagResponse != 0 || header.Flags&ikev2.FlagInitiator == 0 {
		t.Fatalf("probe flags = %#x, want a request from the initiator", header.Flags)
	}
	if header.MessageID == 0 || header.MessageID == authID {
		t.Fatalf("probe message ID = %d, want a new request, not a retransmission of IKE_AUTH (%d)", header.MessageID, authID)
	}
	if _, err := independentOpenAEADIKEPacket(session.Keys.SK_ei, probe); err != nil {
		t.Fatalf("probe is not protected by the IKE SA keys: %v", err)
	}
}
