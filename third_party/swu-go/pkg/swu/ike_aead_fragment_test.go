package swu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"go.uber.org/zap"
)

func TestDecryptSKFUsesCompleteAEADProtection(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	fragment := []byte{0x21, 0x22, 0x23, 0x24}
	packet := independentAEADSKFPacket(t, session, fragment, 1, 2, 7)

	plaintext, fragmentNumber, totalFragments, messageID, err := session.decryptSKF(packet)
	if err != nil {
		t.Fatal("decryptSKF rejected a standards-compliant AEAD fragment")
	}
	if !bytes.Equal(plaintext, fragment) {
		t.Fatal("decryptSKF returned the wrong fragment plaintext")
	}
	if fragmentNumber != 1 || totalFragments != 2 || messageID != 7 {
		t.Fatal("decryptSKF returned the wrong fragment metadata")
	}
	for name, offset := range map[string]int{
		"IKE Header":      23,
		"SKF Header":      ikev2.IKE_HEADER_LEN,
		"Fragment Header": ikev2.IKE_HEADER_LEN + ikev2.PAYLOAD_HEADER_LEN,
	} {
		t.Run(name, func(t *testing.T) {
			tampered := append([]byte(nil), packet...)
			tampered[offset] ^= 0x01
			if _, _, _, _, err := session.decryptSKF(tampered); err == nil {
				t.Fatal("decryptSKF accepted an authenticated-header modification")
			}
		})
	}
}

func TestDecryptSKFRejectsInvalidAEADPadLength(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	packet := independentAEADSKFPacketWithTrailer(t, session, []byte{0x21, 0x22}, 1, 2, 7, []byte{3})
	if _, _, _, _, err := session.decryptSKF(packet); err == nil {
		t.Fatal("decryptSKF accepted an invalid AEAD Pad Length")
	}
}

func TestBuildSKFPacketUsesCompleteAEADProtection(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	fragment := []byte{0x31, 0x32, 0x33, 0x34}
	packet, err := session.buildSKFPacket(fragment, 1, 2, 7, ikev2.IKE_AUTH, ikev2.EAP)
	if err != nil {
		t.Fatal("buildSKFPacket failed")
	}

	plaintext, err := independentOpenAEADSKF(session.Keys.SK_ei, packet)
	if err != nil {
		t.Fatal("independent AES-GCM verifier rejected the outbound SKF packet")
	}
	if !bytes.HasPrefix(plaintext, fragment) {
		t.Fatal("independent verifier recovered the wrong SKF plaintext")
	}
	if len(plaintext) != len(fragment)+1 || plaintext[len(plaintext)-1] != 0 {
		t.Fatal("outbound SKF omitted a valid AEAD Pad Length field")
	}
}

func TestShouldFragmentCountsAEADPadLength(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	session.fragmentationSupported = true
	payload := &ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 7, 0, 5, 1}}
	body, err := payload.Encode()
	if err != nil {
		t.Fatal("encode synthetic EAP payload")
	}
	wireLengthWithoutPadLength := ikev2.IKE_HEADER_LEN + ikev2.PAYLOAD_HEADER_LEN + session.EncAlg.IVSize() + ikev2.PAYLOAD_HEADER_LEN + len(body) + 16
	session.ikeFragmentMTU = uint32(wireLengthWithoutPadLength)

	if !session.shouldFragment([]ikev2.Payload{payload}) {
		t.Fatal("shouldFragment ignored the AEAD Pad Length octet")
	}
}

func TestFragmentMessageKeepsAEADPacketsWithinMTU(t *testing.T) {
	session := newSyntheticAEADTestSession(t)
	session.ikeFragmentMTU = 100
	payload := &ikev2.EncryptedPayloadEAP{EAPMessage: bytes.Repeat([]byte{0x44}, 200)}

	packets, err := session.fragmentMessage([]ikev2.Payload{payload}, ikev2.IKE_AUTH)
	if err != nil {
		t.Fatal("fragmentMessage failed")
	}
	if len(packets) < 2 {
		t.Fatal("fragmentMessage did not produce multiple SKF packets")
	}
	const ipv4AndUDPOverhead = 20 + 8
	for _, packet := range packets {
		if len(packet)+ipv4AndUDPOverhead > int(session.ikeFragmentMTU) {
			t.Fatal("fragmentMessage exceeded the configured MTU")
		}
	}
}

func newSyntheticAEADTestSession(t *testing.T) *Session {
	t.Helper()
	encrypter, err := swucrypto.GetEncrypterWithKeyLen(uint16(ikev2.ENCR_AES_GCM_16), 256)
	if err != nil {
		t.Fatal("create synthetic AEAD encrypter")
	}
	keyLength := encrypter.KeySize() + 4
	return &Session{
		SPIi:      0x0102030405060708,
		SPIr:      0x1112131415161718,
		EncAlg:    encrypter,
		ikeIsAEAD: true,
		Keys: &ikev2.IKESAKeys{
			SK_ei: bytes.Repeat([]byte{0x3c}, keyLength),
			SK_er: bytes.Repeat([]byte{0x5a}, keyLength),
		},
		Logger: zap.NewNop(),
	}
}

func independentAEADSKFPacket(t *testing.T, responder *Session, fragment []byte, fragmentNumber, totalFragments uint16, messageID uint32) []byte {
	t.Helper()
	return independentAEADSKFPacketWithTrailer(t, responder, fragment, fragmentNumber, totalFragments, messageID, []byte{0})
}

func independentAEADSKFPacketWithTrailer(t *testing.T, responder *Session, fragment []byte, fragmentNumber, totalFragments uint16, messageID uint32, trailer []byte) []byte {
	t.Helper()
	keyMaterial := responder.Keys.SK_er
	block, err := aes.NewCipher(keyMaterial[:len(keyMaterial)-4])
	if err != nil {
		t.Fatal("create independent SKF AES cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("create independent SKF AES-GCM")
	}
	plaintext := append([]byte(nil), fragment...)
	plaintext = append(plaintext, trailer...)
	iv := []byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88}
	ciphertextLength := len(plaintext) + gcm.Overhead()

	fragmentHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(fragmentHeader[0:2], fragmentNumber)
	binary.BigEndian.PutUint16(fragmentHeader[2:4], totalFragments)
	nextPayload := ikev2.NoNextPayload
	if fragmentNumber == 1 {
		nextPayload = ikev2.EAP
	}
	skfHeader := (&ikev2.PayloadHeader{
		NextPayload:   nextPayload,
		PayloadLength: uint16(ikev2.PAYLOAD_HEADER_LEN + len(fragmentHeader) + len(iv) + ciphertextLength),
	}).Encode()
	ikeHeader := (&ikev2.IKEHeader{
		SPIi:         responder.SPIi,
		SPIr:         responder.SPIr,
		NextPayload:  ikev2.EncryptedFragment,
		Version:      0x20,
		ExchangeType: ikev2.IKE_AUTH,
		Flags:        ikev2.FlagResponse,
		MessageID:    messageID,
		Length:       uint32(ikev2.IKE_HEADER_LEN + len(skfHeader) + len(fragmentHeader) + len(iv) + ciphertextLength),
	}).Encode()

	aad := make([]byte, 0, len(ikeHeader)+len(skfHeader)+len(fragmentHeader))
	aad = append(aad, ikeHeader...)
	aad = append(aad, skfHeader...)
	aad = append(aad, fragmentHeader...)
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, keyMaterial[len(keyMaterial)-4:]...)
	nonce = append(nonce, iv...)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	packet := make([]byte, 0, len(aad)+len(iv)+len(ciphertext))
	packet = append(packet, aad...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	return packet
}

func independentOpenAEADSKF(keyMaterial, packet []byte) ([]byte, error) {
	const cleartextSKFHeaderLength = ikev2.IKE_HEADER_LEN + ikev2.PAYLOAD_HEADER_LEN + 4
	if len(keyMaterial) <= 4 || len(packet) < cleartextSKFHeaderLength+8 {
		return nil, errors.New("invalid synthetic SKF packet")
	}
	header, err := ikev2.DecodeHeader(packet)
	if err != nil || header.NextPayload != ikev2.EncryptedFragment || header.Length != uint32(len(packet)) {
		return nil, errors.New("invalid synthetic SKF IKE header")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[ikev2.IKE_HEADER_LEN+2 : ikev2.IKE_HEADER_LEN+4]))
	if payloadLength != len(packet)-ikev2.IKE_HEADER_LEN {
		return nil, errors.New("invalid synthetic SKF length")
	}
	block, err := aes.NewCipher(keyMaterial[:len(keyMaterial)-4])
	if err != nil {
		return nil, errors.New("invalid synthetic SKF key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("invalid synthetic SKF AES-GCM")
	}
	ivEnd := cleartextSKFHeaderLength + 8
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, keyMaterial[len(keyMaterial)-4:]...)
	nonce = append(nonce, packet[cleartextSKFHeaderLength:ivEnd]...)
	plaintext, err := gcm.Open(nil, nonce, packet[ivEnd:], packet[:cleartextSKFHeaderLength])
	if err != nil {
		return nil, errors.New("synthetic SKF authentication failed")
	}
	return plaintext, nil
}
