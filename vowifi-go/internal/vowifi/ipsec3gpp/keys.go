package ipsec3gpp

import (
	"errors"
	"fmt"
)

const (
	akaCKLen = 16
	akaIKLen = 16
)

// SecureChannelKeys holds derived ESP encryption and integrity key material.
type SecureChannelKeys struct {
	EncKey  []byte
	AuthKey []byte
}

// DeriveSecureChannelKeys derives ESP keys from CK/IK per 3GPP TS 33.203.
func DeriveSecureChannelKeys(flow Flow) (SecureChannelKeys, error) {
	encKey, err := deriveEncKey(flow.EncAlg, flow.CK)
	if err != nil {
		return SecureChannelKeys{}, err
	}
	authKey, err := deriveAuthKey(flow.AuthAlg, flow.IK)
	if err != nil {
		return SecureChannelKeys{}, err
	}
	return SecureChannelKeys{EncKey: encKey, AuthKey: authKey}, nil
}

func deriveEncKey(encAlg string, ck []byte) ([]byte, error) {
	switch canonicalEncAlg(encAlg) {
	case "aes-cbc":
		return DeriveAESCBCKeyFromCK(ck)
	case "des-ede3-cbc":
		return Derive3DESKeyFromCK(ck)
	case "null":
		return nil, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported encryption algorithm %q", encAlg)
	}
}

func deriveAuthKey(authAlg string, ik []byte) ([]byte, error) {
	switch canonicalAuthAlg(authAlg) {
	case "hmac-sha-1-96":
		return DeriveHMACSHA1KeyFromIK(ik)
	case "hmac-md5-96":
		return DeriveHMACMD5KeyFromIK(ik)
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported authentication algorithm %q", authAlg)
	}
}

// DeriveAESCBCKeyFromCK returns CK_IM for AES-CBC-128 (TS 33.203).
func DeriveAESCBCKeyFromCK(ck []byte) ([]byte, error) {
	if len(ck) < akaCKLen {
		return nil, errors.New("ipsec3gpp: CK too short for AES-CBC")
	}
	return append([]byte(nil), ck[:akaCKLen]...), nil
}

// Derive3DESKeyFromCK expands CK_IM into a 24-byte 3DES key with odd parity.
func Derive3DESKeyFromCK(ck []byte) ([]byte, error) {
	if len(ck) < akaCKLen {
		return nil, errors.New("ipsec3gpp: CK too short for 3DES")
	}
	key := make([]byte, 24)
	copy(key[0:8], ck[0:8])
	copy(key[8:16], ck[8:16])
	copy(key[16:24], ck[0:8])
	for i := range key {
		key[i] = setDESOddParityByte(key[i])
	}
	return key, nil
}

// DeriveHMACSHA1KeyFromIK appends 32 zero bits to IK_IM for HMAC-SHA-1-96.
func DeriveHMACSHA1KeyFromIK(ik []byte) ([]byte, error) {
	if len(ik) < akaIKLen {
		return nil, errors.New("ipsec3gpp: IK too short for HMAC-SHA-1-96")
	}
	out := make([]byte, 20)
	copy(out, ik[:akaIKLen])
	return out, nil
}

// DeriveHMACMD5KeyFromIK uses the first 16 bytes of IK_IM for HMAC-MD5-96.
func DeriveHMACMD5KeyFromIK(ik []byte) ([]byte, error) {
	if len(ik) < akaIKLen {
		return nil, errors.New("ipsec3gpp: IK too short for HMAC-MD5-96")
	}
	return append([]byte(nil), ik[:akaIKLen]...), nil
}

func setDESOddParityByte(b byte) byte {
	parity := byte(0)
	for i := 0; i < 7; i++ {
		if b&(1<<uint(i)) != 0 {
			parity ^= 1
		}
	}
	if parity == 0 {
		b |= 1 << 7
	} else {
		b &^= 1 << 7
	}
	return b
}