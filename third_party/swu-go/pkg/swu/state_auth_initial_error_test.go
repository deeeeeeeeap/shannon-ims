package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

type ikeAuthInitialDiagnostic interface {
	error
	Stage() string
	Result() string
	NotifyType() string
	ProtocolID() uint8
	DataLen() int
}

type authInitialTestSIM struct{}

func (authInitialTestSIM) GetIMSI() (string, error) { return "synthetic-imsi", nil }
func (authInitialTestSIM) CalculateAKA([]byte, []byte) ([]byte, []byte, []byte, []byte, error) {
	return nil, nil, nil, nil, nil
}
func (authInitialTestSIM) Close() error { return nil }

func TestConnectClassifiesInitialIKEAuthErrorNotify(t *testing.T) {
	err := connectWithInitialIKEAuthPayloads(t, []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{
			ProtocolID: 1,
			NotifyType: 24,
			NotifyData: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "error_notify" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
	if diagnostic.NotifyType() != "authentication_failed" || diagnostic.ProtocolID() != 1 || diagnostic.DataLen() != 4 {
		t.Fatalf("diagnostic notify metadata = %q/%d/%d", diagnostic.NotifyType(), diagnostic.ProtocolID(), diagnostic.DataLen())
	}
}

func TestInitialIKEAuthDiagnosticDoesNotExposeNotifyData(t *testing.T) {
	const privateMarker = "synthetic-private-notify-data"
	err := connectWithInitialIKEAuthPayloads(t, []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{
			ProtocolID: 1,
			NotifyType: ikev2.AUTHENTICATION_FAILED,
			NotifyData: []byte(privateMarker),
		},
	})
	if err == nil {
		t.Fatal("Connect() unexpectedly accepted an error Notify")
	}
	if strings.Contains(err.Error(), privateMarker) {
		t.Fatal("typed initial IKE_AUTH error exposed raw Notify Data")
	}
}

func TestConnectClassifiesInitialIKEAuthMissingEAP(t *testing.T) {
	err := connectWithInitialIKEAuthPayloads(t, []ikev2.Payload{
		&ikev2.EncryptedPayloadNotify{NotifyType: ikev2.MOBIKE_SUPPORTED},
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "missing_eap" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
	if diagnostic.NotifyType() != "" || diagnostic.ProtocolID() != 0 || diagnostic.DataLen() != 0 {
		t.Fatal("missing EAP diagnostics unexpectedly included Notify metadata")
	}
}

func TestConnectClassifiesInitialIKEAuthDecryptFailure(t *testing.T) {
	err := connectWithInitialIKEAuthResponse(t, func(session *Session, messageID uint32) []byte {
		response := syntheticEncryptedIKEAuthResponse(t, session, messageID, []ikev2.Payload{
			&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}},
		})
		response[len(response)-1] ^= 0x01
		return response
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "decrypt_failed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func TestConnectClassifiesInitialIKEAuthIntegrityFailure(t *testing.T) {
	err := connectWithInitialIKEAuthResponseUsingProposal(t, 1, func(session *Session, messageID uint32) []byte {
		if session.ikeIsAEAD {
			t.Fatal("test requires a non-AEAD IKE proposal")
		}
		response := syntheticEncryptedIKEAuthResponse(t, session, messageID, []ikev2.Payload{
			&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}},
		})
		response[len(response)-1] ^= 0x01
		return response
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "integrity_failed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func TestConnectClassifiesMalformedInitialIKEAuth(t *testing.T) {
	err := connectWithInitialIKEAuthResponse(t, func(session *Session, messageID uint32) []byte {
		response := syntheticEncryptedIKEAuthResponse(t, session, messageID, []ikev2.Payload{
			&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}},
		})
		binary.BigEndian.PutUint16(response[30:32], uint16(len(response)))
		return response
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "malformed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func TestConnectClassifiesInvalidAEADPadLengthAsMalformed(t *testing.T) {
	err := connectWithInitialIKEAuthResponse(t, func(session *Session, messageID uint32) []byte {
		return independentAEADIKEAuthResponseWithTrailer(t, session, messageID, []ikev2.Payload{
			&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 1, 0, 5, 1}},
		}, []byte{0xff})
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "malformed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func TestConnectClassifiesTruncatedInitialIKEAuthAsMalformed(t *testing.T) {
	err := connectWithInitialIKEAuthResponse(t, func(session *Session, messageID uint32) []byte {
		response := make([]byte, ikev2.IKE_HEADER_LEN)
		binary.BigEndian.PutUint64(response[0:8], session.SPIi)
		binary.BigEndian.PutUint64(response[8:16], session.SPIr)
		response[16] = byte(ikev2.SK)
		response[17] = 0x20
		response[18] = byte(ikev2.IKE_AUTH)
		response[19] = ikev2.FlagResponse
		binary.BigEndian.PutUint32(response[20:24], messageID)
		binary.BigEndian.PutUint32(response[24:28], uint32(len(response)))
		return response
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "malformed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func TestConnectClassifiesCanceledInitialIKEAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var transport *initTestTransport
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
			cancel()
		}
	})
	session := NewSession(&Config{
		LocalAddr:    "192.0.2.10",
		EpDGAddr:     "192.0.2.20",
		LocalPort:    45000,
		EpDGPort:     500,
		APN:          "ims.test.invalid",
		FastReauthID: "synthetic-test-id",
		TransportFactory: func(string, string) (Transport, error) {
			return transport, nil
		},
	}, zap.NewNop())

	err := session.Connect(ctx)
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "canceled" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("typed initial IKE_AUTH cancellation did not preserve context.Canceled")
	}
}

func TestConnectAcceptsInitialEAPRequestWithoutFailureDiagnostic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		session      *Session
		transport    *initTestTransport
		authRequests int
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
			authRequests++
			if authRequests == 1 {
				transport.ikeCh <- syntheticEncryptedIKEAuthResponse(t, session, header.MessageID, []ikev2.Payload{
					&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 7, 0, 5, 1}},
				})
				return
			}
			cancel()
		}
	})
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
	var diagnostic ikeAuthInitialDiagnostic
	if errors.As(err, &diagnostic) {
		t.Fatalf("normal EAP path was classified as %q", diagnostic.Result())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("test did not reach the second IKE_AUTH request")
	}
	if authRequests != 2 {
		t.Fatalf("IKE_AUTH request count = %d, want 2", authRequests)
	}
}

func TestConnectClassifiesMalformedInitialEAPPayload(t *testing.T) {
	err := connectWithInitialIKEAuthPayloads(t, []ikev2.Payload{
		&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1}},
	})
	var diagnostic ikeAuthInitialDiagnostic
	if !errors.As(err, &diagnostic) {
		t.Fatal("Connect() did not return typed initial IKE_AUTH diagnostics")
	}
	if diagnostic.Stage() != "ike_auth_initial" || diagnostic.Result() != "malformed" {
		t.Fatalf("diagnostic stage/result = %q/%q", diagnostic.Stage(), diagnostic.Result())
	}
}

func connectWithInitialIKEAuthPayloads(t *testing.T, payloads []ikev2.Payload) error {
	t.Helper()
	return connectWithInitialIKEAuthResponse(t, func(session *Session, messageID uint32) []byte {
		return syntheticEncryptedIKEAuthResponse(t, session, messageID, payloads)
	})
}

func connectWithInitialIKEAuthResponse(t *testing.T, buildResponse func(*Session, uint32) []byte) error {
	t.Helper()
	return connectWithInitialIKEAuthResponseUsingProposal(t, 0, buildResponse)
}

func connectWithInitialIKEAuthResponseUsingProposal(t *testing.T, proposalIndex int, buildResponse func(*Session, uint32) []byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var (
		session   *Session
		transport *initTestTransport
	)
	transport = newInitTestTransport(func(request []byte) {
		header, err := ikev2.DecodeHeader(request)
		if err != nil {
			cancel()
			return
		}
		switch header.ExchangeType {
		case ikev2.IKE_SA_INIT:
			transport.ikeCh <- syntheticSuccessfulIKESAInitResponseWithProposal(t, request, 0x1112131415161718, proposalIndex)
		case ikev2.IKE_AUTH:
			transport.ikeCh <- buildResponse(session, header.MessageID)
		}
	})
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

	return session.Connect(ctx)
}

func syntheticEncryptedIKEAuthResponse(t *testing.T, initiator *Session, messageID uint32, payloads []ikev2.Payload) []byte {
	t.Helper()
	if initiator.Keys == nil {
		t.Fatal("initiator IKE keys are unavailable")
	}
	responder := &Session{
		SPIi:      initiator.SPIi,
		SPIr:      initiator.SPIr,
		EncAlg:    initiator.EncAlg,
		IntegAlg:  initiator.IntegAlg,
		ikeIsAEAD: initiator.ikeIsAEAD,
		Keys: &ikev2.IKESAKeys{
			SK_ei: append([]byte(nil), initiator.Keys.SK_er...),
			SK_ai: append([]byte(nil), initiator.Keys.SK_ar...),
		},
	}
	response, err := responder.encryptAndWrapWithMsgID(payloads, ikev2.IKE_AUTH, messageID, true)
	if err != nil {
		t.Fatal("failed to build synthetic IKE_AUTH response")
	}
	return response
}
