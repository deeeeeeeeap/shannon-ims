package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// IntegrityAlgorithm 完整性算法接口
type IntegrityAlgorithm interface {
	// Compute 计算 MAC
	Compute(key, data []byte) []byte
	// Verify 验证 MAC
	Verify(key, data, expectedMAC []byte) bool
	// Output 长度
	OutputSize() int
	// Key 长度
	KeySize() int
}

// HMAC-SHA1-96 (截断到 96 位 = 12 字节)
type hmacSHA1_96 struct{}

func (h *hmacSHA1_96) Compute(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:12] // 截断到 96 位
}

func (h *hmacSHA1_96) Verify(key, data, expectedMAC []byte) bool {
	computed := h.Compute(key, data)
	return hmac.Equal(computed, expectedMAC)
}

func (h *hmacSHA1_96) OutputSize() int { return 12 }
func (h *hmacSHA1_96) KeySize() int    { return 20 } // SHA1 输出大小

// HMAC-SHA256-128 (截断到 128 位 = 16 字节)
type hmacSHA256_128 struct{}

func (h *hmacSHA256_128) Compute(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:16]
}

func (h *hmacSHA256_128) Verify(key, data, expectedMAC []byte) bool {
	computed := h.Compute(key, data)
	return hmac.Equal(computed, expectedMAC)
}

func (h *hmacSHA256_128) OutputSize() int { return 16 }
func (h *hmacSHA256_128) KeySize() int    { return 32 }

// HMAC-SHA512-256 (截断到 256 位 = 32 字节)
type hmacSHA512_256 struct{}

func (h *hmacSHA512_256) Compute(key, data []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:32]
}

func (h *hmacSHA512_256) Verify(key, data, expectedMAC []byte) bool {
	computed := h.Compute(key, data)
	return hmac.Equal(computed, expectedMAC)
}

func (h *hmacSHA512_256) OutputSize() int { return 32 }
func (h *hmacSHA512_256) KeySize() int    { return 64 }

// 空完整性算法 (用于 AEAD 或测试)
type nullIntegrity struct{}

func (h *nullIntegrity) Compute(key, data []byte) []byte   { return nil }
func (h *nullIntegrity) Verify(key, data, mac []byte) bool { return true }
func (h *nullIntegrity) OutputSize() int                   { return 0 }
func (h *nullIntegrity) KeySize() int                      { return 0 }

// HMAC-SHA384-192 (截断到 192 位 = 24 字节)
type hmacSHA384_192 struct{}

func (h *hmacSHA384_192) Compute(key, data []byte) []byte {
	mac := hmac.New(sha512.New384, key)
	mac.Write(data)
	return mac.Sum(nil)[:24]
}

func (h *hmacSHA384_192) Verify(key, data, expectedMAC []byte) bool {
	computed := h.Compute(key, data)
	return hmac.Equal(computed, expectedMAC)
}

func (h *hmacSHA384_192) OutputSize() int { return 24 }
func (h *hmacSHA384_192) KeySize() int    { return 48 }

// GetIntegrityAlgorithm 根据 ID 获取完整性算法
func GetIntegrityAlgorithm(id uint16) (IntegrityAlgorithm, error) {
	switch id {
	case 0:
		return &nullIntegrity{}, nil
	case 2: // AUTH_HMAC_SHA1_96
		return &hmacSHA1_96{}, nil
	case 12: // AUTH_HMAC_SHA2_256_128
		return &hmacSHA256_128{}, nil
	case 13: // AUTH_HMAC_SHA2_384_192
		return &hmacSHA384_192{}, nil
	case 14: // AUTH_HMAC_SHA2_512_256
		return &hmacSHA512_256{}, nil
	default:
		return nil, errors.New("不支持的完整性算法")
	}
}

// ComputeHMAC 通用 HMAC 计算函数
func ComputeHMAC(hashFunc func() hash.Hash, key, data []byte) []byte {
	h := hmac.New(hashFunc, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC 通用 HMAC 验证函数
func VerifyHMAC(hashFunc func() hash.Hash, key, data, expectedMAC []byte) bool {
	computed := ComputeHMAC(hashFunc, key, data)
	return hmac.Equal(computed, expectedMAC[:len(computed)])
}
