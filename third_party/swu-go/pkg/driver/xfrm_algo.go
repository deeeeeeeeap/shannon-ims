package driver

import (
	"fmt"
)

// IKEv2 算法 ID → Linux XFRM 内核算法名称的映射

// XFRMCryptAlgo 加密算法描述
type XFRMCryptAlgo struct {
	Name    string // 内核算法名称 (如 "cbc(aes)")
	KeyBits int    // 密钥位数 (不含 salt)
}

// XFRMAuthAlgo 完整性算法描述
type XFRMAuthAlgo struct {
	Name         string // 内核算法名称 (如 "hmac(sha256)")
	KeyBits      int    // 密钥位数
	TruncateBits int    // 截断位数 (ICV 长度)
}

// XFRMAeadAlgo AEAD 算法描述
type XFRMAeadAlgo struct {
	Name    string // 内核算法名称 (如 "rfc4106(gcm(aes))")
	KeyBits int    // 密钥位数 (含 4 字节 salt = 32 位)
	ICVBits int    // ICV 位数
}

// IKEv2AlgToXFRMCrypt 将 IKEv2 加密算法 ID 映射为 XFRM 内核加密算法
// 仅用于非 AEAD 算法 (如 AES-CBC)
func IKEv2AlgToXFRMCrypt(ikeAlgID uint16, keyLenBits int) (*XFRMCryptAlgo, error) {
	if keyLenBits == 0 {
		keyLenBits = 128 // 默认 AES-128
	}

	switch ikeAlgID {
	case 12: // ENCR_AES_CBC
		return &XFRMCryptAlgo{
			Name:    "cbc(aes)",
			KeyBits: keyLenBits,
		}, nil
	case 13: // ENCR_AES_CTR
		return &XFRMCryptAlgo{
			Name:    "rfc3686(ctr(aes))",
			KeyBits: keyLenBits,
		}, nil
	default:
		return nil, fmt.Errorf("不支持的 XFRM 加密算法 ID: %d", ikeAlgID)
	}
}

// IKEv2AlgToXFRMAuth 将 IKEv2 完整性算法 ID 映射为 XFRM 内核完整性算法
func IKEv2AlgToXFRMAuth(ikeAlgID uint16) (*XFRMAuthAlgo, error) {
	switch ikeAlgID {
	case 1: // AUTH_HMAC_MD5_96
		return &XFRMAuthAlgo{
			Name:         "hmac(md5)",
			KeyBits:      128,
			TruncateBits: 96,
		}, nil
	case 2: // AUTH_HMAC_SHA1_96
		return &XFRMAuthAlgo{
			Name:         "hmac(sha1)",
			KeyBits:      160,
			TruncateBits: 96,
		}, nil
	case 12: // AUTH_HMAC_SHA2_256_128
		return &XFRMAuthAlgo{
			Name:         "hmac(sha256)",
			KeyBits:      256,
			TruncateBits: 128,
		}, nil
	case 13: // AUTH_HMAC_SHA2_384_192
		return &XFRMAuthAlgo{
			Name:         "hmac(sha384)",
			KeyBits:      384,
			TruncateBits: 192,
		}, nil
	case 14: // AUTH_HMAC_SHA2_512_256
		return &XFRMAuthAlgo{
			Name:         "hmac(sha512)",
			KeyBits:      512,
			TruncateBits: 256,
		}, nil
	default:
		return nil, fmt.Errorf("不支持的 XFRM 完整性算法 ID: %d", ikeAlgID)
	}
}

// IKEv2AlgToXFRMAead 将 IKEv2 AEAD 算法 ID 映射为 XFRM 内核 AEAD 算法
// keyLenBits 是加密密钥位数 (不含 salt)；内核需要的 key = encKey + salt (4 bytes)
func IKEv2AlgToXFRMAead(ikeAlgID uint16, keyLenBits int) (*XFRMAeadAlgo, error) {
	if keyLenBits == 0 {
		keyLenBits = 128 // 默认 AES-128
	}

	switch ikeAlgID {
	case 18: // ENCR_AES_GCM_8
		return &XFRMAeadAlgo{
			Name:    "rfc4106(gcm(aes))",
			KeyBits: keyLenBits + 32, // 加 4 字节 salt
			ICVBits: 64,
		}, nil
	case 19: // ENCR_AES_GCM_12
		return &XFRMAeadAlgo{
			Name:    "rfc4106(gcm(aes))",
			KeyBits: keyLenBits + 32,
			ICVBits: 96,
		}, nil
	case 20: // ENCR_AES_GCM_16
		return &XFRMAeadAlgo{
			Name:    "rfc4106(gcm(aes))",
			KeyBits: keyLenBits + 32,
			ICVBits: 128,
		}, nil
	case 14: // ENCR_AES_CCM_8
		return &XFRMAeadAlgo{
			Name:    "rfc4309(ccm(aes))",
			KeyBits: keyLenBits + 24, // 加 3 字节 salt
			ICVBits: 64,
		}, nil
	case 15: // ENCR_AES_CCM_12
		return &XFRMAeadAlgo{
			Name:    "rfc4309(ccm(aes))",
			KeyBits: keyLenBits + 24,
			ICVBits: 96,
		}, nil
	case 16: // ENCR_AES_CCM_16
		return &XFRMAeadAlgo{
			Name:    "rfc4309(ccm(aes))",
			KeyBits: keyLenBits + 24,
			ICVBits: 128,
		}, nil
	default:
		return nil, fmt.Errorf("不支持的 XFRM AEAD 算法 ID: %d", ikeAlgID)
	}
}

// IsAEADAlgorithm 判断 IKEv2 加密算法 ID 是否为 AEAD 算法
func IsAEADAlgorithm(ikeAlgID uint16) bool {
	switch ikeAlgID {
	case 14, 15, 16, // AES-CCM-*
		18, 19, 20: // AES-GCM-*
		return true
	default:
		return false
	}
}
