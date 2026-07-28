package ikev2

import (
	"errors"
	"fmt"
)

type IKEPacket struct {
	Header   *IKEHeader
	Payloads []Payload
}

func NewIKEPacket() *IKEPacket {
	return &IKEPacket{
		Header:   &IKEHeader{},
		Payloads: []Payload{},
	}
}

func (p *IKEPacket) Encode() ([]byte, error) {
	// 1. 按顺序编码载荷
	var payloadsData []byte

	// 我们需要设置每个通用载荷头部的 NextPayload 字段
	// 逻辑: Header.NextPayload 指向 Payloads[0].Type
	// Payloads[0].Header.NextPayload 指向 Payloads[1].Type ...

	if len(p.Payloads) > 0 {
		p.Header.NextPayload = p.Payloads[0].Type()
	} else {
		p.Header.NextPayload = NoNextPayload
	}

	for i, pl := range p.Payloads {
		// 计算当前载荷的下一个载荷类型
		nextPlType := NoNextPayload
		if i < len(p.Payloads)-1 {
			nextPlType = p.Payloads[i+1].Type()
		}

		// 编码载荷主体
		body, err := pl.Encode()
		if err != nil {
			return nil, err
		}

		// 创建通用头部
		genHeader := &PayloadHeader{
			NextPayload:   nextPlType,
			Critical:      false, // 目前默认为 false
			PayloadLength: uint16(PAYLOAD_HEADER_LEN + len(body)),
		}

		headerBytes := genHeader.Encode()
		payloadsData = append(payloadsData, headerBytes...)
		payloadsData = append(payloadsData, body...)
	}

	// 2. 更新头部长度
	p.Header.Length = uint32(IKE_HEADER_LEN + len(payloadsData))

	// 3. 编码头部
	headerBytes := p.Header.Encode()

	return append(headerBytes, payloadsData...), nil
}

func DecodePacket(data []byte) (*IKEPacket, error) {
	// 1. 解码头部
	header, err := DecodeHeader(data)
	if err != nil {
		return nil, err
	}

	packet := &IKEPacket{
		Header:   header,
		Payloads: []Payload{},
	}

	// 2. 遍历载荷
	offset := IKE_HEADER_LEN
	nextPayloadType := header.NextPayload

	for nextPayloadType != NoNextPayload && offset < len(data) {
		// 读取通用头部
		if offset+PAYLOAD_HEADER_LEN > len(data) {
			return nil, errors.New("数据包太短，无法包含载荷头部")
		}

		genHeader, err := DecodePayloadHeader(data[offset : offset+PAYLOAD_HEADER_LEN])
		if err != nil {
			return nil, err
		}

		payloadLen := int(genHeader.PayloadLength)
		if offset+payloadLen > len(data) {
			return nil, errors.New("数据包太短，无法包含载荷主体")
		}

		payloadBody := data[offset+PAYLOAD_HEADER_LEN : offset+payloadLen]

		// 使用 nextPayloadType 确定如何解码主体
		var payload Payload

		switch nextPayloadType {
		case SA:
			// 待办: 我们需要单独处理加密载荷 (SK)，因为
			// 它包含其他载荷。但可能需要递归解码。
			// 目前，让我们先处理 SA。
			// 理想情况下我们需要一个全面的 switch。
			// 等等，简单的修复：对于 SA，我们解码 Proposal 等。
			// 但是对于加密载荷，我们就保留为字节吗？还是立即解密？
			// 在这个阶段 (协议定义)，我们只是解码结构，没有加密上下文。
			// 所以 EncryptedPayload (SK) 应该存储加密的字节。
			payload, err = DecodePayloadSA(payloadBody)
		case KE:
			payload, err = DecodePayloadKE(payloadBody)
		case NiNr:
			payload, err = DecodePayloadNonce(payloadBody)
		case IDi:
			payload, err = DecodePayloadID(payloadBody, true)
		case IDr:
			payload, err = DecodePayloadID(payloadBody, false)
		case AUTH:
			payload, err = DecodePayloadAuth(payloadBody)
		case EAP:
			payload, err = DecodePayloadEAP(payloadBody)
		case N:
			payload, err = DecodePayloadNotify(payloadBody)
		case D:
			payload, err = DecodePayloadDelete(payloadBody)
		case TSI:
			payload, err = DecodePayloadTS(payloadBody, true)
		case TSR:
			payload, err = DecodePayloadTS(payloadBody, false)
		case CP:
			payload, err = DecodePayloadCP(payloadBody)
		default:
			// 未知或尚未实现的载荷
			// 我们可以将其存储为通用的 RawPayload
			payload = &RawPayload{
				PType: nextPayloadType,
				Data:  payloadBody,
			}
		}

		if err != nil {
			return nil, fmt.Errorf("解码载荷类型 %d 失败: %v", nextPayloadType, err)
		}

		packet.Payloads = append(packet.Payloads, payload)

		// 准备下一个
		nextPayloadType = genHeader.NextPayload
		offset += payloadLen
	}

	return packet, nil
}

// RawPayload 用于未知类型
type RawPayload struct {
	PType PayloadType
	Data  []byte
}

func (p *RawPayload) Type() PayloadType       { return p.PType }
func (p *RawPayload) Encode() ([]byte, error) { return p.Data, nil }
