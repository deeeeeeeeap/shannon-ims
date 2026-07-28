package ipsec

import (
	"sync"
	"sync/atomic"

	"github.com/1239t/swu-go/pkg/crypto"
)

type SecurityAssociation struct {
	SPI           uint32
	RemoteSPI     uint32
	EncryptionAlg crypto.Encrypter
	EncryptionKey []byte
	IntegritySalt []byte // 用于 GCM

	IntegrityAlg  crypto.PRF                // 旧接口 (保留兼容性)
	IntegrityAlg2 crypto.IntegrityAlgorithm // 新接口，用于非 AEAD
	IntegrityKey  []byte

	IsAEAD         bool   // 是否使用 AEAD 加密 (GCM 等)
	SequenceNumber uint64 // 使用 64 来模拟 ESN 或只是防止溢出
	ReplayWindow   uint64 // 用于检查重复项

	mu sync.Mutex
}

func NewSecurityAssociation(spi uint32, enc crypto.Encrypter, encKey []byte, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         true, // 默认假设 AEAD (GCM)
	}
}

// NewSecurityAssociationCBC 创建使用 CBC + HMAC 的 SA
func NewSecurityAssociationCBC(spi uint32, enc crypto.Encrypter, encKey []byte, integAlg crypto.IntegrityAlgorithm, integKey []byte) *SecurityAssociation {
	return &SecurityAssociation{
		SPI:            spi,
		EncryptionAlg:  enc,
		EncryptionKey:  encKey,
		IntegrityAlg2:  integAlg,
		IntegrityKey:   integKey,
		SequenceNumber: 0,
		IsAEAD:         false,
	}
}

func (sa *SecurityAssociation) NextSequenceNumber() uint32 {
	return uint32(atomic.AddUint64(&sa.SequenceNumber, 1))
}
