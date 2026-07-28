package ikev2

import (
	"encoding/binary"
	"errors"
)

type Payload interface {
	Type() PayloadType
	Encode() ([]byte, error)
}

// 通用载荷头部 (RFC 7296 3.2 节)
// 每个 IKE 载荷都以通用载荷头部开始
type PayloadHeader struct {
	NextPayload   PayloadType
	Critical      bool
	Reserved      uint8 // 7 位
	PayloadLength uint16
}

const PAYLOAD_HEADER_LEN = 4

func (h *PayloadHeader) Encode() []byte {
	buf := make([]byte, PAYLOAD_HEADER_LEN)
	buf[0] = uint8(h.NextPayload)
	if h.Critical {
		buf[1] = 0x80 // 设置最高有效位
	}
	// buf[1] |= h.Reserved & 0x7F // 保留位必须为零
	binary.BigEndian.PutUint16(buf[2:4], h.PayloadLength)
	return buf
}

func DecodePayloadHeader(data []byte) (*PayloadHeader, error) {
	if len(data) < PAYLOAD_HEADER_LEN {
		return nil, errors.New("通用载荷头部太短")
	}
	return &PayloadHeader{
		NextPayload:   PayloadType(data[0]),
		Critical:      (data[1] & 0x80) != 0,
		Reserved:      data[1] & 0x7F,
		PayloadLength: binary.BigEndian.Uint16(data[2:4]),
	}, nil
}
