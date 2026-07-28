package swu

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestConnectAcceptsIndependentAEADIKEAuthFixture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
				transport.ikeCh <- independentAEADIKEAuthResponse(t, session, header.MessageID, []ikev2.Payload{
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
		t.Fatalf("standards-compliant AEAD response was classified as %q", diagnostic.Result())
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("test did not reach the second IKE_AUTH request")
	}
	if authRequests != 2 {
		t.Fatalf("IKE_AUTH request count = %d, want 2", authRequests)
	}
}

func TestConnectSendsStandardsCompliantAEADIKEAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var (
		session      *Session
		transport    *initTestTransport
		authRequests int
		openErr      error
		plaintext    []byte
		firstPayload ikev2.PayloadType
		outbound     []byte
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
			outbound = append([]byte(nil), request...)
			plaintext, openErr = independentOpenAEADIKEPacket(session.Keys.SK_ei, request)
			if len(request) > ikev2.IKE_HEADER_LEN {
				firstPayload = ikev2.PayloadType(request[ikev2.IKE_HEADER_LEN])
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
	if openErr != nil {
		t.Fatal("independent AES-GCM verifier rejected the outbound IKE_AUTH request")
	}
	if err := validateIndependentAEADPlaintext(plaintext, firstPayload); err != nil {
		t.Fatal("outbound IKE_AUTH omitted a valid AEAD Pad Length field")
	}
	tamperedIKEHeader := append([]byte(nil), outbound...)
	tamperedIKEHeader[23] ^= 0x01
	if _, err := independentOpenAEADIKEPacket(session.Keys.SK_ei, tamperedIKEHeader); err == nil {
		t.Fatal("independent verifier accepted a modified IKE Header")
	}
	tamperedSKHeader := append([]byte(nil), outbound...)
	tamperedSKHeader[ikev2.IKE_HEADER_LEN] ^= 0x01
	if _, err := independentOpenAEADIKEPacket(session.Keys.SK_ei, tamperedSKHeader); err == nil {
		t.Fatal("independent verifier accepted a modified SK Header")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal("test did not stop after inspecting the first IKE_AUTH request")
	}
	if authRequests != 1 {
		t.Fatalf("IKE_AUTH request count = %d, want 1", authRequests)
	}
}

func TestDecryptAndParseRejectsInvalidAEADPadLength(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	packet := independentAEADIKEAuthResponseWithTrailer(t, session, 0, []ikev2.Payload{
		&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 7, 0, 5, 1}},
	}, []byte{2})

	if _, _, err := session.decryptAndParse(packet); err == nil {
		t.Fatal("decryptAndParse accepted an invalid AEAD Pad Length")
	}
}

func independentAEADIKEAuthResponse(t *testing.T, initiator *Session, messageID uint32, payloads []ikev2.Payload) []byte {
	t.Helper()
	return independentAEADIKEAuthResponseWithTrailer(t, initiator, messageID, payloads, []byte{0})
}

func independentAEADIKEAuthResponseWithTrailer(t *testing.T, initiator *Session, messageID uint32, payloads []ikev2.Payload, trailer []byte) []byte {
	t.Helper()
	if initiator.Keys == nil || !initiator.ikeIsAEAD {
		t.Fatal("initiator AEAD IKE keys are unavailable")
	}

	innerData := make([]byte, 0)
	for index, payload := range payloads {
		nextPayload := ikev2.NoNextPayload
		if index+1 < len(payloads) {
			nextPayload = payloads[index+1].Type()
		}
		body, err := payload.Encode()
		if err != nil {
			t.Fatal("encode synthetic IKE_AUTH payload")
		}
		payloadHeader := (&ikev2.PayloadHeader{
			NextPayload:   nextPayload,
			PayloadLength: uint16(ikev2.PAYLOAD_HEADER_LEN + len(body)),
		}).Encode()
		innerData = append(innerData, payloadHeader...)
		innerData = append(innerData, body...)
	}
	innerData = append(innerData, trailer...)

	keyMaterial := initiator.Keys.SK_er
	if len(keyMaterial) <= 4 {
		t.Fatal("responder AEAD key material is unavailable")
	}
	block, err := aes.NewCipher(keyMaterial[:len(keyMaterial)-4])
	if err != nil {
		t.Fatal("create independent AES cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("create independent AES-GCM")
	}
	iv := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	ciphertextLen := len(innerData) + gcm.Overhead()

	firstPayload := ikev2.NoNextPayload
	if len(payloads) > 0 {
		firstPayload = payloads[0].Type()
	}
	skHeader := (&ikev2.PayloadHeader{
		NextPayload:   firstPayload,
		PayloadLength: uint16(ikev2.PAYLOAD_HEADER_LEN + len(iv) + ciphertextLen),
	}).Encode()
	ikeHeader := (&ikev2.IKEHeader{
		SPIi:         initiator.SPIi,
		SPIr:         initiator.SPIr,
		NextPayload:  ikev2.SK,
		Version:      0x20,
		ExchangeType: ikev2.IKE_AUTH,
		Flags:        ikev2.FlagResponse,
		MessageID:    messageID,
		Length:       uint32(ikev2.IKE_HEADER_LEN + len(skHeader) + len(iv) + ciphertextLen),
	}).Encode()

	aad := make([]byte, 0, len(ikeHeader)+len(skHeader))
	aad = append(aad, ikeHeader...)
	aad = append(aad, skHeader...)
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, keyMaterial[len(keyMaterial)-4:]...)
	nonce = append(nonce, iv...)
	ciphertext := gcm.Seal(nil, nonce, innerData, aad)

	packet := make([]byte, 0, len(aad)+len(iv)+len(ciphertext))
	packet = append(packet, aad...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	return packet
}

func independentOpenAEADIKEPacket(keyMaterial, packet []byte) ([]byte, error) {
	if len(keyMaterial) <= 4 || len(packet) < ikev2.IKE_HEADER_LEN+ikev2.PAYLOAD_HEADER_LEN+8 {
		return nil, errors.New("invalid synthetic AEAD packet")
	}
	header, err := ikev2.DecodeHeader(packet)
	if err != nil || header.NextPayload != ikev2.SK || header.Length != uint32(len(packet)) {
		return nil, errors.New("invalid synthetic IKE header")
	}
	skPayloadLength := int(binary.BigEndian.Uint16(packet[ikev2.IKE_HEADER_LEN+2 : ikev2.IKE_HEADER_LEN+4]))
	if skPayloadLength != len(packet)-ikev2.IKE_HEADER_LEN {
		return nil, errors.New("invalid synthetic SK length")
	}

	block, err := aes.NewCipher(keyMaterial[:len(keyMaterial)-4])
	if err != nil {
		return nil, errors.New("invalid synthetic AEAD key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("invalid synthetic AES-GCM")
	}
	aadEnd := ikev2.IKE_HEADER_LEN + ikev2.PAYLOAD_HEADER_LEN
	ivEnd := aadEnd + 8
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, keyMaterial[len(keyMaterial)-4:]...)
	nonce = append(nonce, packet[aadEnd:ivEnd]...)
	plaintext, err := gcm.Open(nil, nonce, packet[ivEnd:], packet[:aadEnd])
	if err != nil {
		return nil, errors.New("synthetic AEAD authentication failed")
	}
	return plaintext, nil
}

func validateIndependentAEADPlaintext(plaintext []byte, firstPayload ikev2.PayloadType) error {
	offset := 0
	nextPayload := firstPayload
	for nextPayload != ikev2.NoNextPayload {
		if offset+ikev2.PAYLOAD_HEADER_LEN > len(plaintext) {
			return errors.New("truncated synthetic payload header")
		}
		payloadLength := int(binary.BigEndian.Uint16(plaintext[offset+2 : offset+4]))
		if payloadLength < ikev2.PAYLOAD_HEADER_LEN || offset+payloadLength > len(plaintext) {
			return errors.New("invalid synthetic payload length")
		}
		nextPayload = ikev2.PayloadType(plaintext[offset])
		offset += payloadLength
	}
	if offset >= len(plaintext) {
		return errors.New("missing synthetic Pad Length")
	}
	padLength := int(plaintext[len(plaintext)-1])
	if len(plaintext)-offset != padLength+1 {
		return errors.New("invalid synthetic padding")
	}
	return nil
}
