package ipsec3gpp

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"errors"
)

type nullEncrypter struct{}

func (e *nullEncrypter) IVSize() int    { return 0 }
func (e *nullEncrypter) BlockSize() int { return 1 }
func (e *nullEncrypter) KeySize() int   { return 0 }

func (e *nullEncrypter) Encrypt(plaintext, key, iv, aad []byte) ([]byte, error) {
	_ = key
	_ = iv
	_ = aad
	return append([]byte(nil), plaintext...), nil
}

func (e *nullEncrypter) Decrypt(ciphertext, key, iv, aad []byte) ([]byte, error) {
	_ = key
	_ = iv
	_ = aad
	return append([]byte(nil), ciphertext...), nil
}

type tripleDESCBC struct{}

func (e *tripleDESCBC) IVSize() int    { return des.BlockSize }
func (e *tripleDESCBC) BlockSize() int { return des.BlockSize }
func (e *tripleDESCBC) KeySize() int   { return 24 }

func (e *tripleDESCBC) Encrypt(plaintext, key, iv, aad []byte) ([]byte, error) {
	_ = aad
	if len(plaintext)%des.BlockSize != 0 {
		return nil, errors.New("ipsec3gpp: 3DES plaintext not block aligned")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out, nil
}

func (e *tripleDESCBC) Decrypt(ciphertext, key, iv, aad []byte) ([]byte, error) {
	_ = aad
	if len(ciphertext)%des.BlockSize != 0 {
		return nil, errors.New("ipsec3gpp: 3DES ciphertext not block aligned")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

type hmacMD596 struct{}

func (h *hmacMD596) Compute(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)[:12]
}

func (h *hmacMD596) Verify(key, data, expectedMAC []byte) bool {
	return hmac.Equal(h.Compute(key, data), expectedMAC)
}

func (h *hmacMD596) OutputSize() int { return 12 }
func (h *hmacMD596) KeySize() int    { return 16 }