package ikev2

import (
	"encoding/binary"
	"errors"
)

// 密钥交换载荷 (RFC 7296 3.4 节)
type EncryptedPayloadKE struct {
	DHGroup AlgorithmType
	KEData  []byte
}

func (p *EncryptedPayloadKE) Type() PayloadType { return KE }

func (p *EncryptedPayloadKE) Encode() ([]byte, error) {
	// 头部: 4 字节 (DH 组 + 保留) + 数据
	buf := make([]byte, 4+len(p.KEData))
	binary.BigEndian.PutUint16(buf[0:2], uint16(p.DHGroup))
	binary.BigEndian.PutUint16(buf[2:4], 0) // 保留
	copy(buf[4:], p.KEData)
	return buf, nil
}

func DecodePayloadKE(data []byte) (*EncryptedPayloadKE, error) {
	if len(data) < 4 {
		return nil, errors.New("KE 载荷太短")
	}
	return &EncryptedPayloadKE{
		DHGroup: AlgorithmType(binary.BigEndian.Uint16(data[0:2])),
		KEData:  data[4:],
	}, nil
}

// Nonce 载荷 (RFC 7296 3.10 节)
type EncryptedPayloadNonce struct {
	NonceData []byte
}

func (p *EncryptedPayloadNonce) Type() PayloadType { return NiNr } // 或者是 N ? 不，载荷类型 40 是 Nonce。等等，constants.go 说 NiNr = 40。正确。

func (p *EncryptedPayloadNonce) Encode() ([]byte, error) {
	return p.NonceData, nil
}

func DecodePayloadNonce(data []byte) (*EncryptedPayloadNonce, error) {
	return &EncryptedPayloadNonce{NonceData: data}, nil
}
