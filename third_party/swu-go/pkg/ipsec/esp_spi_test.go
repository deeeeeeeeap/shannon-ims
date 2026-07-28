package ipsec

import (
	"bytes"
	"testing"
)

type testEncrypter struct{}

func (t testEncrypter) Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

func (t testEncrypter) Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

func (t testEncrypter) IVSize() int    { return 0 }
func (t testEncrypter) BlockSize() int { return 4 }
func (t testEncrypter) KeySize() int   { return 16 }

func TestEncapsulateUsesLocalSPI(t *testing.T) {
	sa := &SecurityAssociation{
		SPI:           0x01020304,
		EncryptionAlg: testEncrypter{},
		EncryptionKey: make([]byte, 16),
		IsAEAD:        true,
	}

	plaintext := []byte{0x45, 0x00, 0x00, 0x14}
	pkt, err := Encapsulate(plaintext, sa)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	if len(pkt) < 4 {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	if !bytes.Equal(pkt[:4], []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("SPI mismatch: %x", pkt[:4])
	}

	out, err := Decapsulate(pkt, sa)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Fatalf("plaintext mismatch: got=%x want=%x", out, plaintext)
	}
}

func TestDecapsulateRejectsMismatchedSPI(t *testing.T) {
	sa := &SecurityAssociation{
		SPI:           0x0a0b0c0d,
		EncryptionAlg: testEncrypter{},
		EncryptionKey: make([]byte, 16),
		IsAEAD:        true,
	}

	plaintext := []byte{0x60, 0x00, 0x00, 0x00}
	pkt, err := Encapsulate(plaintext, sa)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}

	other := &SecurityAssociation{
		SPI:           0x01020304,
		EncryptionAlg: testEncrypter{},
		EncryptionKey: make([]byte, 16),
		IsAEAD:        true,
	}
	if _, err := Decapsulate(pkt, other); err == nil {
		t.Fatalf("expected error for SPI mismatch")
	}
}
