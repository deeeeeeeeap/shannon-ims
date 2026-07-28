package swu

import (
	"bytes"
	"testing"

	swucrypto "github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

func TestFirstIKEAuthEncryptionDoesNotMutateResponderKey(t *testing.T) {
	encrypter, err := swucrypto.GetEncrypterWithKeyLen(uint16(ikev2.ENCR_AES_GCM_16), 128)
	if err != nil {
		t.Fatal("create synthetic IKE AES-GCM encrypter")
	}
	keyLength := encrypter.KeySize() + 4
	keyMaterial := make([]byte, keyLength*2+32)
	copy(keyMaterial[:keyLength], bytes.Repeat([]byte{0x31}, keyLength))
	copy(keyMaterial[keyLength:keyLength*2], bytes.Repeat([]byte{0x52}, keyLength))
	session := &Session{
		SPIi:      0x0102030405060708,
		SPIr:      0x1112131415161718,
		EncAlg:    encrypter,
		ikeIsAEAD: true,
		Keys: &ikev2.IKESAKeys{
			SK_ei: keyMaterial[:keyLength],
			SK_er: keyMaterial[keyLength : keyLength*2],
		},
	}
	responderKeyBefore := append([]byte(nil), session.Keys.SK_er...)

	if _, err := session.encryptAndWrapWithMsgID([]ikev2.Payload{
		&ikev2.EncryptedPayloadEAP{EAPMessage: []byte{1, 7, 0, 5, 1}},
	}, ikev2.IKE_AUTH, 0, false); err != nil {
		t.Fatal("encrypt first synthetic IKE_AUTH")
	}
	if !bytes.Equal(session.Keys.SK_er, responderKeyBefore) {
		t.Fatal("first IKE_AUTH encryption modified SK_er")
	}
}
