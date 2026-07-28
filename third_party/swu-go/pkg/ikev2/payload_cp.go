package ikev2

import (
	"encoding/binary"
	"fmt"
)

// Configuration Payload (RFC 7296 Section 3.6)
type EncryptedPayloadCP struct {
	CFGType    uint8
	Attributes []*CPAttribute
}

const (
	CFG_REQUEST = 1
	CFG_REPLY   = 2
	CFG_SET     = 3
	CFG_ACK     = 4
)

// Configuration Attributes
const (
	INTERNAL_IP4_ADDRESS       = 1
	INTERNAL_IP4_NETMASK       = 2
	INTERNAL_IP4_DNS           = 3
	INTERNAL_IP4_NBNS          = 4
	INTERNAL_IP4_DHCP          = 6
	APPLICATION_VERSION        = 7
	INTERNAL_IP6_ADDRESS       = 8
	INTERNAL_IP6_DNS           = 10
	INTERNAL_IP6_DHCP          = 12
	INTERNAL_IP4_SUBNET        = 13
	SUPPORTED_ATTRIBUTES       = 14
	P_CSCF_IP4_ADDRESS         = 20
	P_CSCF_IP6_ADDRESS         = 21
	ASSIGNED_PCSCF_IP6_ADDRESS = 16390
)

func (p *EncryptedPayloadCP) Type() PayloadType { return CP }

func (p *EncryptedPayloadCP) Encode() ([]byte, error) {
	// Header: 1 CFG Type + 3 Reserved + Attributes
	var attrsBody []byte
	for _, attr := range p.Attributes {
		b, err := attr.Encode()
		if err != nil {
			return nil, err
		}
		attrsBody = append(attrsBody, b...)
	}

	buf := make([]byte, 4+len(attrsBody))
	buf[0] = p.CFGType
	// buf[1:4] Reserved = 0
	copy(buf[4:], attrsBody)

	return buf, nil
}

// CP Attribute
type CPAttribute struct {
	Type  uint16
	Value []byte
}

func (a *CPAttribute) Encode() ([]byte, error) {
	// TLV 格式: 2 字节 Type (MSB=0) + 2 字节 Length + Value
	// RFC 说: "属性... 格式为 Type/Length/Value... Length 字段表示 Value 字段的字节长度。"
	// 注意: 与 Transform Attributes 不同，CP Attributes 始终是 TLV。

	buf := make([]byte, 4+len(a.Value))
	binary.BigEndian.PutUint16(buf[0:2], a.Type)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))
	copy(buf[4:], a.Value)
	return buf, nil
}

// DecodePayloadCP 解码 Configuration Payload (CP)
// 数据格式: CFGType(1) + Reserved(3) + Attributes...
func DecodePayloadCP(data []byte) (*EncryptedPayloadCP, error) {
	if len(data) < 4 {
		return nil, errPayloadTooShort("CP")
	}

	p := &EncryptedPayloadCP{
		CFGType:    data[0],
		Attributes: []*CPAttribute{},
	}

	// 解析属性
	offset := 4
	for offset < len(data) {
		attr, bytesRead, err := decodeCPAttribute(data[offset:])
		if err != nil {
			return nil, err
		}
		p.Attributes = append(p.Attributes, attr)
		offset += bytesRead
	}

	return p, nil
}

// decodeCPAttribute 解码单个 CP 属性
// 格式: Type(2) + Length(2) + Value(Length)
func decodeCPAttribute(data []byte) (*CPAttribute, int, error) {
	if len(data) < 4 {
		return nil, 0, errPayloadTooShort("CP Attribute")
	}

	rawType := binary.BigEndian.Uint16(data[0:2])
	af := (rawType & 0x8000) != 0
	attrType := rawType & 0x7fff
	if af {
		v := make([]byte, 2)
		copy(v, data[2:4])
		return &CPAttribute{Type: attrType, Value: v}, 4, nil
	}

	attrLen := int(binary.BigEndian.Uint16(data[2:4]))

	if len(data) < 4+attrLen {
		return nil, 0, errPayloadTooShort("CP Attribute Value")
	}

	attr := &CPAttribute{
		Type:  attrType,
		Value: make([]byte, attrLen),
	}
	copy(attr.Value, data[4:4+attrLen])

	return attr, 4 + attrLen, nil
}

// errPayloadTooShort 返回载荷太短的错误
func errPayloadTooShort(name string) error {
	return fmt.Errorf("%s 载荷数据太短", name)
}
