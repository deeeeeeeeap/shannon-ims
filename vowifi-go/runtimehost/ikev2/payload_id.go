package ikev2

import (
	"errors"
)

// 身份标识载荷 (RFC 7296 3.5 节)
type EncryptedPayloadID struct {
	IDType      uint8
	IDData      []byte
	IsInitiator bool // 辅助字段，用于确定 Type() 返回值
}

const (
	ID_IPV4_ADDR   = 1
	ID_FQDN        = 2
	ID_RFC822_ADDR = 3
	ID_IPV6_ADDR   = 5
	ID_DER_ASN1_DN = 9
	ID_DER_ASN1_GN = 10
	ID_KEY_ID      = 11
)

func (p *EncryptedPayloadID) Type() PayloadType {
	if p.IsInitiator {
		return IDi
	}
	return IDr
}

func (p *EncryptedPayloadID) Encode() ([]byte, error) {
	// 头部: 1 字节 ID 类型 + 3 字节保留 + 数据
	buf := make([]byte, 4+len(p.IDData))
	buf[0] = p.IDType
	// buf[1:4] 保留 = 0
	copy(buf[4:], p.IDData)
	return buf, nil
}

func DecodePayloadID(data []byte, isInitiator bool) (*EncryptedPayloadID, error) {
	if len(data) < 4 {
		return nil, errors.New("ID 载荷太短")
	}
	return &EncryptedPayloadID{
		IDType:      data[0],
		IDData:      data[4:], // 复制还是切片？只读切片是可以的
		IsInitiator: isInitiator,
	}, nil
}
