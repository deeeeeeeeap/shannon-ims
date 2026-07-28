package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// 加密接口
type Encrypter interface {
	Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error)
	IVSize() int
	BlockSize() int
	KeySize() int // 返回密钥长度 (不含盐)
}

// AES-CBC
type aesCBC struct {
	blockSize int
	keySize   int
}

func (e *aesCBC) IVSize() int    { return aes.BlockSize }
func (e *aesCBC) BlockSize() int { return aes.BlockSize }
func (e *aesCBC) KeySize() int   { return e.keySize }

func (e *aesCBC) Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 填充应该由调用者处理 (ESP 填充是特定的)
	// 但标准 AES-CBC 要求输入是块对齐的。
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("明文未对齐块")
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func (e *aesCBC) Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("密文未对齐块")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// AES-GCM
type aesGCM struct {
	icvSize int
	keySize int
}

func (e *aesGCM) IVSize() int { return 8 } // RFC 4106: ESP 中使用的 8 字节 IV (Nonce)

func (e *aesGCM) BlockSize() int { return 16 } // GCM 流密码，但基于块
func (e *aesGCM) KeySize() int   { return e.keySize }

func (e *aesGCM) Encrypt(plaintext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	// IKEv2/IPsec 中的 GCM 密钥结构: [密钥 (16/24/32 字节) | 盐 (4 字节)]
	if len(key) < 4 {
		return nil, errors.New("GCM 盐的密钥太短")
	}
	realKeyLength := len(key) - 4
	realKey := key[:realKeyLength:realKeyLength]
	salt := key[realKeyLength:len(key):len(key)]

	block, err := aes.NewCipher(realKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 12) // 标准 12 字节 nonce (4 盐 + 8 IV)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 0, len(salt)+len(iv))
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...) // 4 字节盐 + 8 字节 IV = 12 字节

	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func (e *aesGCM) Decrypt(ciphertext []byte, key []byte, iv []byte, aad []byte) ([]byte, error) {
	if len(key) < 4 {
		return nil, errors.New("GCM 盐的密钥太短")
	}
	realKeyLength := len(key) - 4
	realKey := key[:realKeyLength:realKeyLength]
	salt := key[realKeyLength:len(key):len(key)]

	block, err := aes.NewCipher(realKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 0, len(salt)+len(iv))
	nonce = append(nonce, salt...)
	nonce = append(nonce, iv...)
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// 工厂函数
func GetEncrypter(id uint16) (Encrypter, error) {
	return GetEncrypterWithKeyLen(id, 0)
}

func GetEncrypterWithKeyLen(id uint16, keyLenBits int) (Encrypter, error) {
	keySize := 16
	if keyLenBits != 0 {
		if keyLenBits%8 != 0 {
			return nil, errors.New("无效的密钥长度")
		}
		keySize = keyLenBits / 8
	}

	switch id {
	case 12: // AES_CBC
		return &aesCBC{keySize: keySize}, nil
	case 18, 19, 20: // AES_GCM_8/12/16
		return &aesGCM{icvSize: 16, keySize: keySize}, nil
	default:
		return nil, errors.New("不支持的加密算法")
	}
}

// 随机数生成
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}
