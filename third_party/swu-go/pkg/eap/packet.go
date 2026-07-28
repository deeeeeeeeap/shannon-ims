package eap

import (
	"encoding/binary"
	"errors"
)

// EAP 代码
const (
	CodeRequest  = 1
	CodeResponse = 2
	CodeSuccess  = 3
	CodeFailure  = 4
)

// EAP 类型
const (
	TypeIdentity = 1
	TypeAKA      = 23 // EAP-AKA (RFC 4187, 4G)
	TypeAKAPrime = 50 // EAP-AKA' (RFC 5448, 5G)
)

// EAP-AKA 子类型
const (
	SubtypeChallenge        = 1
	SubtypeAuthReject       = 2
	SubtypeSyncFailure      = 4
	SubtypeIdentity         = 5
	SubtypeReauthentication = 13 // Fast Re-authentication (RFC 4187 §5)
	SubtypeNotificationAlt  = 12 // 部分 ePDG (如 O2) 使用非标 subtype 发送 Notification
)

// AKA 属性
const (
	AT_RAND              = 1
	AT_AUTN              = 2
	AT_RES               = 3
	AT_AUTS              = 4
	AT_PADDING           = 6
	AT_NONCE_MT          = 7
	AT_PERMANENT_ID_REQ  = 10
	AT_MAC               = 11
	AT_NOTIFICATION      = 12
	AT_ANY_ID_REQ        = 13
	AT_IDENTITY          = 14
	AT_VERSION_LIST      = 15
	AT_FULLAUTH_ID_REQ   = 17
	AT_COUNTER           = 19
	AT_COUNTER_TOO_SMALL = 20
	AT_NONCE_S           = 21
	AT_CLIENT_ERROR_CODE = 22
	AT_CHECKCODE         = 23
	AT_KDF_INPUT         = 23  // AKA' 专用: 网络名称输入 (RFC 5448 §3.1)，与 AT_CHECKCODE 共用编号但在 Type 50 下语义不同
	AT_KDF               = 24  // AKA' 专用: KDF 协商标识 (RFC 5448 §3.2)
	AT_IV                = 129 // 加密向量 (RFC 4187 §10.12)
	AT_ENCR_DATA         = 130 // 加密数据 (RFC 4187 §10.12)
	AT_NEXT_PSEUDONYM    = 132 // 下次的临时假名
	AT_NEXT_REAUTH_ID    = 133 // 下次的快速重认证 ID (RFC 4187 §10.15)
	AT_RESULT_IND        = 135 // 结果指示 (O2/EE 等运营商 Challenge 常见)
)

type EAPPacket struct {
	Code       uint8
	Identifier uint8
	Type       uint8  // 仅当 Code 为 Request/Response 时
	Subtype    uint8  // 仅当 Type 为 AKA 时
	Data       []byte // 原始数据 (AKA 的属性)
}

func Parse(data []byte) (*EAPPacket, error) {
	if len(data) < 4 {
		return nil, errors.New("EAP packet too short")
	}

	p := &EAPPacket{
		Code:       data[0],
		Identifier: data[1],
	}
	length := binary.BigEndian.Uint16(data[2:4])

	if int(length) > len(data) {
		return nil, errors.New("EAP length exceeds data")
	}

	currentLen := 4
	if p.Code == CodeRequest || p.Code == CodeResponse {
		if length > 4 {
			p.Type = data[4]
			currentLen++

			if p.Type == TypeAKA || p.Type == TypeAKAPrime {
				if length > 5 {
					p.Subtype = data[5]
					// EAP-AKA/AKA' 格式: Code, ID, Len, Type, Subtype, Reserved(2), Attributes...
					currentLen += 3 // Subtype(1) + Reserved(2)

					if length > 8 {
						p.Data = data[8:length]
					}
				}
			} else {
				p.Data = data[5:length]
			}
		}
	}
	// 对于 Success/Failure，通常没有 Type/Data。

	return p, nil
}

func (p *EAPPacket) Encode() []byte {
	length := 4
	if p.Code == CodeRequest || p.Code == CodeResponse {
		length++ // Type
		if p.Type == TypeAKA || p.Type == TypeAKAPrime {
			length += 3 // 子类型 + 保留
			length += len(p.Data)
		} else {
			length += len(p.Data)
		}
	}

	buf := make([]byte, length)
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))

	if p.Code == CodeRequest || p.Code == CodeResponse {
		buf[4] = p.Type
		if p.Type == TypeAKA || p.Type == TypeAKAPrime {
			buf[5] = p.Subtype
			buf[6] = 0 // Reserved
			buf[7] = 0
			copy(buf[8:], p.Data)
		} else {
			copy(buf[5:], p.Data)
		}
	}

	return buf
}

// 属性辅助函数
type Attribute struct {
	Type   uint8
	Length uint8 // in 4-byte words
	Value  []byte
}

func (a *Attribute) Encode() []byte {
	// 长度包括 Type 和 Length 字节。
	// 定义为 4 字节字的乘数。
	// 值长度必须填充。

	valLen := len(a.Value)
	totalLen := 2 + valLen
	padLen := 0
	if totalLen%4 != 0 {
		padLen = 4 - (totalLen % 4)
	}
	totalLen += padLen

	a.Length = uint8(totalLen / 4)

	buf := make([]byte, totalLen)
	buf[0] = a.Type
	buf[1] = a.Length
	copy(buf[2:], a.Value)
	// 填充为零，已由 make 设置

	return buf
}

func ParseAttributes(data []byte) (map[uint8]*Attribute, error) {
	attrs := make(map[uint8]*Attribute)
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		aType := data[offset]
		aLen := int(data[offset+1]) * 4 // 长度以字节为单位

		if aLen == 0 {
			return nil, errors.New("attribute length zero")
		}
		if offset+aLen > len(data) {
			return nil, errors.New("attribute length exceeds data")
		}

		// Value 是 Bytes 2 .. Length
		val := data[offset+2 : offset+aLen]
		// 移除填充？填充是否严格取决于 Type？
		// 通常我们只存储包括填充的整个值块
		// 解析器逻辑应知道要读取多少字节以获取特定信息 (RAND=16)

		attrs[aType] = &Attribute{
			Type:   aType,
			Length: data[offset+1],
			Value:  val,
		}

		offset += aLen
	}
	return attrs, nil
}
