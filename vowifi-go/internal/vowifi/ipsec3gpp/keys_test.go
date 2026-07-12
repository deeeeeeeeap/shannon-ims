package ipsec3gpp

import (
	"bytes"
	"testing"
)

func TestDeriveSecureChannelKeysAESCBCHMACSHA1(t *testing.T) {
	ck := bytes.Repeat([]byte{0x11}, 16)
	ik := bytes.Repeat([]byte{0x22}, 16)
	keys, err := DeriveSecureChannelKeys(Flow{
		AuthAlg: "hmac-sha-1-96",
		EncAlg:  "aes-cbc",
		CK:      ck,
		IK:      ik,
	})
	if err != nil {
		t.Fatalf("DeriveSecureChannelKeys: %v", err)
	}
	if !bytes.Equal(keys.EncKey, ck) {
		t.Fatalf("enc key mismatch: %x", keys.EncKey)
	}
	if len(keys.AuthKey) != 20 {
		t.Fatalf("auth key len %d, want 20", len(keys.AuthKey))
	}
	if !bytes.Equal(keys.AuthKey[:16], ik) || !bytes.Equal(keys.AuthKey[16:], make([]byte, 4)) {
		t.Fatalf("auth key mismatch: %x", keys.AuthKey)
	}
}