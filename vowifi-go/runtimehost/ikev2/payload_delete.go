package ikev2

import (
	"encoding/binary"
	"errors"
)

// 删除载荷 (RFC 7296 3.11 节)
type EncryptedPayloadDelete struct {
	ProtocolID ProtocolID
	SPISize    uint8
	NumSPIs    uint16
	SPIs       []byte // SPISize * NumSPIs bytes
}

func (p *EncryptedPayloadDelete) Type() PayloadType { return D }

func (p *EncryptedPayloadDelete) Encode() ([]byte, error) {
	// 头部: 1 协议 ID + 1 SPI 大小 + 2 SPI 数量 + SPIs
	buf := make([]byte, 4+len(p.SPIs))

	buf[0] = uint8(p.ProtocolID)
	buf[1] = p.SPISize
	binary.BigEndian.PutUint16(buf[2:4], p.NumSPIs)
	copy(buf[4:], p.SPIs)

	return buf, nil
}

// DecodePayloadDelete 解码删除载荷
func DecodePayloadDelete(data []byte) (*EncryptedPayloadDelete, error) {
	if len(data) < 4 {
		return nil, errors.New("删除载荷太短")
	}

	protoID := ProtocolID(data[0])
	spiSize := data[1]
	numSPIs := binary.BigEndian.Uint16(data[2:4])

	expectedLen := 4 + int(spiSize)*int(numSPIs)
	if len(data) < expectedLen {
		return nil, errors.New("删除载荷对于 SPI 数据来说太短")
	}

	return &EncryptedPayloadDelete{
		ProtocolID: protoID,
		SPISize:    spiSize,
		NumSPIs:    numSPIs,
		SPIs:       data[4:expectedLen],
	}, nil
}
