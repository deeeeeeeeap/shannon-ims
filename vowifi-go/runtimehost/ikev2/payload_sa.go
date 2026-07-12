package ikev2

import (
	"encoding/binary"
	"errors"
)

// SA 载荷 (RFC 7296 3.3 节)
type EncryptedPayloadSA struct {
	Proposals []*Proposal
}

func (p *EncryptedPayloadSA) Type() PayloadType { return SA }

func (p *EncryptedPayloadSA) Encode() ([]byte, error) {
	var payloadBody []byte
	for i, prop := range p.Proposals {
		prop.LastProposal = (i == len(p.Proposals)-1)
		b, err := prop.Encode()
		if err != nil {
			return nil, err
		}
		payloadBody = append(payloadBody, b...)
	}
	return payloadBody, nil
}

// Proposal 子结构 (RFC 7296 3.3.1 节)
type Proposal struct {
	LastProposal bool
	ProposalNum  uint8
	ProtocolID   ProtocolID
	SPI          []byte
	Transforms   []*Transform
}

const PROPOSAL_HEADER_LEN = 8

func (p *Proposal) Encode() ([]byte, error) {
	var transformsBody []byte
	for i, t := range p.Transforms {
		t.LastTransform = (i == len(p.Transforms)-1)
		b, err := t.Encode()
		if err != nil {
			return nil, err
		}
		transformsBody = append(transformsBody, b...)
	}

	totalLen := PROPOSAL_HEADER_LEN + len(p.SPI) + len(transformsBody)
	buf := make([]byte, PROPOSAL_HEADER_LEN+len(p.SPI))

	if p.LastProposal {
		buf[0] = 0 // Last
	} else {
		buf[0] = 2 // More
	}
	buf[1] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	buf[4] = p.ProposalNum
	buf[5] = uint8(p.ProtocolID)
	buf[6] = uint8(len(p.SPI))
	buf[7] = uint8(len(p.Transforms))

	copy(buf[PROPOSAL_HEADER_LEN:], p.SPI)
	return append(buf, transformsBody...), nil
}

// Transform 子结构 (RFC 7296 3.3.2 节)
type Transform struct {
	LastTransform bool
	Type          TransformType
	ID            AlgorithmType
	Attributes    []*TransformAttribute
}

const TRANSFORM_HEADER_LEN = 8

func (t *Transform) Encode() ([]byte, error) {
	var attrsBody []byte
	for _, attr := range t.Attributes {
		b, err := attr.Encode()
		if err != nil {
			return nil, err
		}
		attrsBody = append(attrsBody, b...)
	}

	totalLen := TRANSFORM_HEADER_LEN + len(attrsBody)
	buf := make([]byte, TRANSFORM_HEADER_LEN)

	if t.LastTransform {
		buf[0] = 0 // Last
	} else {
		buf[0] = 3 // More
	}
	buf[1] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	buf[4] = uint8(t.Type)
	buf[5] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[6:8], uint16(t.ID))

	return append(buf, attrsBody...), nil
}

// Transform 属性 (RFC 7296 3.3.5 节)
type TransformAttribute struct {
	Type  uint16
	Value []byte // For TLV
	Val   uint16 // For TV
}

func (a *TransformAttribute) Encode() ([]byte, error) {
	// TV Format: Attributes with values from 0 to 65535 (2 bytes)
	// TLV Format: Attributes with variable length values
	// The MSB of the Attribute Type indicates the format.
	// 0 = TLV, 1 = TV. But RFC 7296 Section 3.3.5 says:
	// "If the AF bit is zero... Indicated by setting the high order bit..."
	// Wait, RFC says: "AF (1 bit) - Attribute Format. If the AF bit is a zero, then the Data Attribute follows the TLV format... If the AF bit is a one, then the Data Attribute follows the TV format."

	// Basic check: if Value slice is empty, we assume TV format using Val.
	// If Value slice is not empty, we use TLV format.

	if len(a.Value) > 0 {
		// TLV
		// Type (2 bytes) with MSB 0
		// Length (2 bytes)
		// Value (variable)
		buf := make([]byte, 4+len(a.Value))
		binary.BigEndian.PutUint16(buf[0:2], a.Type&0x7FFF) // Ensure MSB is 0
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))
		copy(buf[4:], a.Value)
		return buf, nil
	} else {
		// TV
		// Type (2 bytes) with MSB 1
		// Value (2 bytes)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf[0:2], a.Type|0x8000) // Ensure MSB is 1
		binary.BigEndian.PutUint16(buf[2:4], a.Val)
		return buf, nil
	}
}

// 创建 Proposals/Transforms 的辅助函数

func NewProposal(num uint8, proto ProtocolID, spi []byte) *Proposal {
	return &Proposal{
		ProposalNum: num,
		ProtocolID:  proto,
		SPI:         spi,
	}
}

func (p *Proposal) AddTransform(tType TransformType, tID AlgorithmType, keyLen int) {
	// keyLen 仅用于具有可变密钥长度的加密算法 (例如 AES-CBC)
	attrs := []*TransformAttribute{}
	if keyLen > 0 {
		attrs = append(attrs, &TransformAttribute{
			Type: AttributeKeyLength,
			Val:  uint16(keyLen),
		})
	}

	p.Transforms = append(p.Transforms, &Transform{
		Type:       tType,
		ID:         tID,
		Attributes: attrs,
	})
}
func DecodePayloadSA(data []byte) (*EncryptedPayloadSA, error) {
	// SA 载荷包含一个或多个 Proposal
	var proposals []*Proposal
	offset := 0

	for offset < len(data) {
		// Read Proposal Length from header (bytes 2-4)
		if offset+4 > len(data) {
			return nil, errors.New("SA 载荷对于 Proposal 头部来说太短")
		}
		propLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if offset+propLen > len(data) {
			return nil, errors.New("SA 载荷对于 Proposal 主体来说太短")
		}

		propData := data[offset : offset+propLen]
		prop, err := DecodeProposal(propData)
		if err != nil {
			return nil, err
		}
		proposals = append(proposals, prop)

		// 检查是否是最后一个 proposal
		if prop.LastProposal {
			break
		}
		// 如果 Last 字段为 0 (Last) 但我们有更多数据，RFC 说是 2 (More)，等待。
		// Proposal 头部字节 0: 0=Last, 2=More.
		// 在 DecodeProposal 内部处理？不，我们需要检查这个字节。
		if data[offset] == 0 {
			break
		}

		offset += propLen
	}

	return &EncryptedPayloadSA{Proposals: proposals}, nil
}

func DecodeProposal(data []byte) (*Proposal, error) {
	if len(data) < PROPOSAL_HEADER_LEN {
		return nil, errors.New("Proposal too short")
	}

	p := &Proposal{
		LastProposal: data[0] == 0,
		ProposalNum:  data[4],
		ProtocolID:   ProtocolID(data[5]),
	}

	spiSize := int(data[6])
	transformCount := int(data[7])

	if len(data) < PROPOSAL_HEADER_LEN+spiSize {
		return nil, errors.New("Proposal too short for SPI")
	}

	p.SPI = make([]byte, spiSize)
	copy(p.SPI, data[PROPOSAL_HEADER_LEN:PROPOSAL_HEADER_LEN+spiSize])

	// Decode Transforms
	offset := PROPOSAL_HEADER_LEN + spiSize
	for i := 0; i < transformCount; i++ {
		if offset >= len(data) {
			return nil, errors.New("Proposal too short for Transforms")
		}

		// 我们需要查看长度以知道要读取多少
		if offset+4 > len(data) {
			return nil, errors.New("Proposal too short for Transform header")
		}
		transLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))

		if offset+transLen > len(data) {
			return nil, errors.New("Proposal too short for Transform body")
		}

		trans, err := DecodeTransform(data[offset : offset+transLen])
		if err != nil {
			return nil, err
		}
		p.Transforms = append(p.Transforms, trans)
		offset += transLen
	}

	return p, nil
}

func DecodeTransform(data []byte) (*Transform, error) {
	if len(data) < TRANSFORM_HEADER_LEN {
		return nil, errors.New("Transform too short")
	}

	t := &Transform{
		LastTransform: data[0] == 0,
		Type:          TransformType(data[4]),
		ID:            AlgorithmType(binary.BigEndian.Uint16(data[6:8])),
	}

	// 属性紧随头部之后
	offset := TRANSFORM_HEADER_LEN
	for offset < len(data) {
		// Attribute Header is 4 bytes
		if offset+4 > len(data) {
			return nil, errors.New("Transform too short for Attribute header")
		}

		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		afBit := (attrType & 0x8000) != 0
		actualType := attrType & 0x7FFF

		var attr *TransformAttribute
		var attrLen int

		if afBit {
			// TV 格式: 值在长度字段中 (字节 2-4)
			val := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			attr = &TransformAttribute{
				Type: actualType,
				Val:  val,
			}
			attrLen = 4
		} else {
			// TLV 格式: 长度在字节 2-4 中
			valLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
			if offset+4+valLen > len(data) {
				return nil, errors.New("Transform Attribute value truncated")
			}
			val := make([]byte, valLen)
			copy(val, data[offset+4:offset+4+valLen])

			attr = &TransformAttribute{
				Type:  actualType,
				Value: val,
				// Val? 不用于 TLV
			}
			attrLen = 4 + valLen
		}

		t.Attributes = append(t.Attributes, attr)
		offset += attrLen
	}

	return t, nil
}
