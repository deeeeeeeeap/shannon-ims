package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

func TestAESGCMDoesNotMutateKeyOrAdjacentData(t *testing.T) {
	encrypter, err := GetEncrypterWithKeyLen(20, 128)
	if err != nil {
		t.Fatal("create AES-GCM encrypter")
	}
	keyLength := encrypter.KeySize() + 4
	keyAndCanary := make([]byte, keyLength+16)
	copy(keyAndCanary[:keyLength], bytes.Repeat([]byte{0x31}, keyLength))
	copy(keyAndCanary[keyLength:], bytes.Repeat([]byte{0x7d}, 16))
	iv := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	plaintext := []byte("synthetic plaintext")
	aad := []byte("synthetic aad")

	t.Run("Encrypt", func(t *testing.T) {
		backing := append([]byte(nil), keyAndCanary...)
		key := backing[:keyLength]
		before := append([]byte(nil), backing...)
		if _, err := encrypter.Encrypt(plaintext, key, iv, aad); err != nil {
			t.Fatal("AES-GCM Encrypt failed")
		}
		if !bytes.Equal(backing, before) {
			t.Fatal("AES-GCM Encrypt modified key backing storage")
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		ciphertext := independentGCMSeal(t, keyAndCanary[:keyLength], iv, plaintext, aad)
		backing := append([]byte(nil), keyAndCanary...)
		key := backing[:keyLength]
		before := append([]byte(nil), backing...)
		if _, err := encrypter.Decrypt(ciphertext, key, iv, aad); err != nil {
			t.Fatal("AES-GCM Decrypt failed")
		}
		if !bytes.Equal(backing, before) {
			t.Fatal("AES-GCM Decrypt modified key backing storage")
		}
	})
}

func independentGCMSeal(t *testing.T, keyMaterial, iv, plaintext, aad []byte) []byte {
	t.Helper()
	realKeyLength := len(keyMaterial) - 4
	block, err := aes.NewCipher(keyMaterial[:realKeyLength])
	if err != nil {
		t.Fatal("create independent AES cipher")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("create independent AES-GCM")
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, keyMaterial[realKeyLength:]...)
	nonce = append(nonce, iv...)
	return gcm.Seal(nil, nonce, plaintext, aad)
}
