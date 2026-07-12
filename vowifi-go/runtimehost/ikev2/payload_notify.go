package ikev2

import (
	"encoding/binary"
	"errors"
)

// 通知载荷 (RFC 7296 3.10 节)
type EncryptedPayloadNotify struct {
	ProtocolID ProtocolID
	SPI        []byte
	NotifyType uint16
	NotifyData []byte
}

func (p *EncryptedPayloadNotify) Type() PayloadType { return N }

func (p *EncryptedPayloadNotify) Encode() ([]byte, error) {
	// 头部: 1 协议 ID + 1 SPI 大小 + 2 通知类型 + SPI + 数据
	spiLen := len(p.SPI)
	buf := make([]byte, 4+spiLen+len(p.NotifyData))

	buf[0] = uint8(p.ProtocolID)
	buf[1] = uint8(spiLen)
	binary.BigEndian.PutUint16(buf[2:4], p.NotifyType)

	copy(buf[4:], p.SPI)
	copy(buf[4+spiLen:], p.NotifyData)

	return buf, nil
}

func DecodePayloadNotify(data []byte) (*EncryptedPayloadNotify, error) {
	if len(data) < 4 {
		return nil, errors.New("通知载荷太短")
	}

	protoID := ProtocolID(data[0])
	spiLen := int(data[1])
	notifyType := binary.BigEndian.Uint16(data[2:4])

	if len(data) < 4+spiLen {
		return nil, errors.New("通知载荷对于 SPI 来说太短")
	}

	return &EncryptedPayloadNotify{
		ProtocolID: protoID,
		NotifyType: notifyType,
		SPI:        data[4 : 4+spiLen],
		NotifyData: data[4+spiLen:],
	}, nil
}
