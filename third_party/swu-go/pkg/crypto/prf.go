package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

// PRF (伪随机函数) 接口
type PRF interface {
	Hash() hash.Hash
	KeyLen() int
}

type hmacPRF struct {
	newHash func() hash.Hash
	keyLen  int
}

func (h *hmacPRF) Hash() hash.Hash {
	return h.newHash()
}

func (h *hmacPRF) KeyLen() int {
	return h.keyLen
}

var (
	PRF_HMAC_MD5      = &hmacPRF{newHash: md5.New, keyLen: 16}
	PRF_HMAC_SHA1     = &hmacPRF{newHash: sha1.New, keyLen: 20}
	PRF_HMAC_SHA2_256 = &hmacPRF{newHash: sha256.New, keyLen: 32}
	PRF_HMAC_SHA2_384 = &hmacPRF{newHash: sha512.New384, keyLen: 48}
	PRF_HMAC_SHA2_512 = &hmacPRF{newHash: sha512.New, keyLen: 64}
)

// RFC 7296 2.13 节. 生成密钥材料
// prf+ (K,S) = T1 | T2 | T3 | T4 | ...
// T1 = prf (K, S | 0x01)
// T2 = prf (K, T1 | S | 0x02)
// T3 = prf (K, T2 | S | 0x03)
func PrfPlus(prf PRF, key []byte, seed []byte, totalBytes int) ([]byte, error) {
	var result []byte
	var lastBlock []byte
	blockIndex := 1

	for len(result) < totalBytes {
		h := hmac.New(prf.Hash, key)

		if blockIndex == 1 {
			// T1 = prf (K, S | 0x01)
			h.Write(seed)
			h.Write([]byte{byte(blockIndex)})
		} else {
			// Tn = prf (K, Tn-1 | S | n)
			h.Write(lastBlock)
			h.Write(seed)
			h.Write([]byte{byte(blockIndex)})
		}

		lastBlock = h.Sum(nil)
		result = append(result, lastBlock...)
		blockIndex++

		if blockIndex > 255 {
			return nil, errors.New("PRF+ 溢出: 块太多")
		}
	}

	return result[:totalBytes], nil
}

func GetPRF(id uint16) (PRF, error) {
	// 载荷定义中的 ID
	switch id {
	case 1:
		return PRF_HMAC_MD5, nil
	case 2:
		return PRF_HMAC_SHA1, nil
	case 5:
		return PRF_HMAC_SHA2_256, nil
	case 6:
		return PRF_HMAC_SHA2_384, nil
	case 7:
		return PRF_HMAC_SHA2_512, nil
	default:
		return nil, errors.New("不支持的 PRF ID")
	}
}
