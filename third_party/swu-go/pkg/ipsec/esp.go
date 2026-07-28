package ipsec

import (
	"encoding/binary"
	"errors"
	"github.com/1239t/swu-go/pkg/crypto"
)

// ESP 数据包格式
// [ SPI (4) | Seq (4) | IV (var) | Payload ... | Padding ... | PadLen(1) | NextHeader(1) ] [ ICV (var) ]

func Encapsulate(plaintext []byte, sa *SecurityAssociation) ([]byte, error) {
	seq := sa.NextSequenceNumber()

	// 准备头部
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], sa.SPI)
	binary.BigEndian.PutUint32(header[4:8], seq)

	// IV
	ivSize := sa.EncryptionAlg.IVSize()
	iv, err := crypto.RandomBytes(ivSize)
	if err != nil {
		return nil, err
	}

	// 准备载荷 + 填充 + 填充长度 + 下一个头部
	// RFC 4303: 填充以对齐到块大小 (通常 4 字节用于 32 位对齐或特定于算法)
	// AES-CBC 要求 16 字节对齐。
	// AES-GCM 要求 4 字节对齐。
	blockSize := sa.EncryptionAlg.BlockSize()

	// 要加密的数据 = 载荷 + 填充 + 填充长度 + 下一个头部
	// 载荷是 `plaintext` (通常是 IP 数据包)。
	// 下一个头部? 既然我们使用 TUN，载荷是 IPv4 (4) 或 IPv6 (41)。
	// 我们需要检测。
	nextHeader := uint8(0)
	if len(plaintext) > 0 {
		version := plaintext[0] >> 4
		if version == 4 {
			nextHeader = 4
		} else if version == 6 {
			nextHeader = 41
		}
	}

	// 填充计算
	// 需要的长度 = len(plaintext) + 2 (PadLen+NextHeader)
	// 总长度必须是 blockSize 的倍数。
	// 对于 GCM，blockSize 通常是 4 字节用于对齐逻辑 (不是密码块大小)。
	// 对于 CBC，让我们假设是密码块大小，对于 GCM/CTR 是 4？
	// crypto.Encrypter 也许应该提供 AlignSize。
	// 让我们使用接口中的 BlockSize。

	neededLen := len(plaintext) + 2 // + padding
	padLen := 0

	if neededLen%blockSize != 0 {
		padLen = blockSize - (neededLen % blockSize)
	}

	dataToEncrypt := make([]byte, len(plaintext)+padLen+2)
	copy(dataToEncrypt, plaintext)
	for i := 0; i < padLen; i++ {
		dataToEncrypt[len(plaintext)+i] = byte(i + 1)
	}
	dataToEncrypt[len(plaintext)+padLen] = byte(padLen)
	dataToEncrypt[len(plaintext)+padLen+1] = nextHeader

	// 加密
	// GCM 的 AAD: SPI + Seq
	aad := header // First 8 bytes

	ciphertext, err := sa.EncryptionAlg.Encrypt(dataToEncrypt, sa.EncryptionKey, iv, aad)
	if err != nil {
		return nil, err
	}

	encryptedPayload := make([]byte, 0, len(header)+len(iv)+len(ciphertext))
	encryptedPayload = append(encryptedPayload, header...)
	encryptedPayload = append(encryptedPayload, iv...)
	encryptedPayload = append(encryptedPayload, ciphertext...)

	// 完整性 (如果没有 AEAD)
	// 如果 EncryptionAlg 是 GCM，Encrypt 通常会附加 Tag (ICV)。
	// 所以对于 AEAD，encryptedPayload 已经包含 ICV。
	// 对于 CBC + HMAC，需要计算并附加 HMAC。
	if !sa.IsAEAD && sa.IntegrityAlg2 != nil {
		// 计算整个 ESP 包的 HMAC (SPI + Seq + IV + Ciphertext)
		icv := sa.IntegrityAlg2.Compute(sa.IntegrityKey, encryptedPayload)
		encryptedPayload = append(encryptedPayload, icv...)
	}

	return encryptedPayload, nil
}

func Decapsulate(packet []byte, sa *SecurityAssociation) ([]byte, error) {
	if len(packet) < 8 {
		return nil, errors.New("ESP packet too short")
	}

	spi := binary.BigEndian.Uint32(packet[0:4])
	if sa != nil && sa.SPI != 0 && spi != sa.SPI {
		return nil, errors.New("ESP SPI 不匹配")
	}

	seq := binary.BigEndian.Uint32(packet[4:8])
	_ = seq

	ivSize := sa.EncryptionAlg.IVSize()
	if len(packet) < 8+ivSize {
		return nil, errors.New("ESP packet too short for IV")
	}

	// 非 AEAD 完整性验证
	var ciphertextWithICV []byte
	if !sa.IsAEAD && sa.IntegrityAlg2 != nil {
		icvSize := sa.IntegrityAlg2.OutputSize()
		if len(packet) < 8+ivSize+icvSize {
			return nil, errors.New("ESP packet too short for ICV")
		}

		// ICV 在包的末尾
		receivedICV := packet[len(packet)-icvSize:]
		dataToVerify := packet[:len(packet)-icvSize]

		// 验证 HMAC
		if !sa.IntegrityAlg2.Verify(sa.IntegrityKey, dataToVerify, receivedICV) {
			return nil, errors.New("ESP integrity check failed")
		}

		// 剥离 ICV 后解密
		ciphertextWithICV = packet[8+ivSize : len(packet)-icvSize]
	} else {
		// AEAD: ICV 包含在密文中，由 Decrypt 处理
		ciphertextWithICV = packet[8+ivSize:]
	}

	iv := packet[8 : 8+ivSize]
	aad := packet[0:8] // SPI + Seq

	plaintext, err := sa.EncryptionAlg.Decrypt(ciphertextWithICV, sa.EncryptionKey, iv, aad)
	if err != nil {
		return nil, err
	}

	// 移除尾部
	if len(plaintext) < 2 {
		return nil, errors.New("decrypted payload too short")
	}

	padLen := int(plaintext[len(plaintext)-2])
	nextHeader := plaintext[len(plaintext)-1]
	_ = nextHeader

	if len(plaintext) < 2+padLen {
		return nil, errors.New("invalid padding length")
	}

	return plaintext[:len(plaintext)-2-padLen], nil
}
