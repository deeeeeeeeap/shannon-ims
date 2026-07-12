package ikev2

import (
	"encoding/binary"
	"errors"
	"net"
)

// 流量选择器载荷 (RFC 7296 3.13 节)
type EncryptedPayloadTS struct { // TSI or TSR
	IsInitiator      bool
	TrafficSelectors []*TrafficSelector
}

func (p *EncryptedPayloadTS) Type() PayloadType {
	if p.IsInitiator {
		return TSI
	}
	return TSR
}

func (p *EncryptedPayloadTS) Encode() ([]byte, error) {
	// 头部: 1 字节 TS 数量 + 3 保留 + TS
	buf := make([]byte, 4)
	buf[0] = uint8(len(p.TrafficSelectors))

	var tsData []byte
	for _, ts := range p.TrafficSelectors {
		b := ts.Encode()
		tsData = append(tsData, b...)
	}
	return append(buf, tsData...), nil
}

// 流量选择器子结构
type TrafficSelector struct {
	TSType     uint8
	IPProtocol uint8
	StartPort  uint16
	EndPort    uint16
	StartAddr  []byte // 4 字节 (IPv4) 或 16 (IPv6)
	EndAddr    []byte
}

const (
	TS_IPV4_ADDR_RANGE = 7
	TS_IPV6_ADDR_RANGE = 8
)

func NewTrafficSelectorIPV4(startIP, endIP net.IP, startPort, endPort uint16) *TrafficSelector {
	return &TrafficSelector{
		TSType:     TS_IPV4_ADDR_RANGE,
		IPProtocol: 0, // 0 = Any
		StartPort:  startPort,
		EndPort:    endPort,
		StartAddr:  startIP.To4(),
		EndAddr:    endIP.To4(),
	}
}

// NewTrafficSelectorIPV6 创建 IPv6 流量选择器
func NewTrafficSelectorIPV6(startIP, endIP net.IP, startPort, endPort uint16) *TrafficSelector {
	return &TrafficSelector{
		TSType:     TS_IPV6_ADDR_RANGE,
		IPProtocol: 0, // 0 = Any
		StartPort:  startPort,
		EndPort:    endPort,
		StartAddr:  startIP.To16(),
		EndAddr:    endIP.To16(),
	}
}

func (ts *TrafficSelector) Encode() []byte {
	// 长度: IPv4 范围为 16 字节
	length := 16
	if ts.TSType == TS_IPV6_ADDR_RANGE {
		length = 40
	}

	buf := make([]byte, length)
	buf[0] = ts.TSType
	buf[1] = ts.IPProtocol
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	binary.BigEndian.PutUint16(buf[4:6], ts.StartPort)
	binary.BigEndian.PutUint16(buf[6:8], ts.EndPort)

	if ts.TSType == TS_IPV4_ADDR_RANGE {
		copy(buf[8:12], ts.StartAddr)
		copy(buf[12:16], ts.EndAddr)
	} else {
		copy(buf[8:24], ts.StartAddr)
		copy(buf[24:40], ts.EndAddr)
	}

	return buf
}

func DecodePayloadTS(data []byte, isInitiator bool) (*EncryptedPayloadTS, error) {
	if len(data) < 4 {
		return nil, errors.New("TS 载荷太短")
	}
	tsCount := int(data[0])
	offset := 4

	out := &EncryptedPayloadTS{
		IsInitiator:      isInitiator,
		TrafficSelectors: make([]*TrafficSelector, 0, tsCount),
	}

	for i := 0; i < tsCount; i++ {
		if offset+8 > len(data) {
			return nil, errors.New("TS 载荷对于选择器头部来说太短")
		}
		tType := data[offset]
		ipProto := data[offset+1]
		length := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if length < 8 || offset+length > len(data) {
			return nil, errors.New("TS 载荷对于选择器主体来说太短")
		}

		startPort := binary.BigEndian.Uint16(data[offset+4 : offset+6])
		endPort := binary.BigEndian.Uint16(data[offset+6 : offset+8])
		rest := data[offset+8 : offset+length]

		var startAddr, endAddr []byte
		switch tType {
		case TS_IPV4_ADDR_RANGE:
			if length != 16 || len(rest) != 8 {
				return nil, errors.New("TS IPv4 选择器长度非法")
			}
			startAddr = append([]byte(nil), rest[0:4]...)
			endAddr = append([]byte(nil), rest[4:8]...)
		case TS_IPV6_ADDR_RANGE:
			if length != 40 || len(rest) != 32 {
				return nil, errors.New("TS IPv6 选择器长度非法")
			}
			startAddr = append([]byte(nil), rest[0:16]...)
			endAddr = append([]byte(nil), rest[16:32]...)
		default:
			return nil, errors.New("不支持的 TS 类型")
		}

		out.TrafficSelectors = append(out.TrafficSelectors, &TrafficSelector{
			TSType:     tType,
			IPProtocol: ipProto,
			StartPort:  startPort,
			EndPort:    endPort,
			StartAddr:  startAddr,
			EndAddr:    endAddr,
		})
		offset += length
	}

	return out, nil
}
