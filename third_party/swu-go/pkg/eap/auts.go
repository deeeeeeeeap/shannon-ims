package eap

import (
	"encoding/binary"
	"errors"
)

// AUTS 同步失败响应
// 当 AUTN 验证失败 (SQN 不同步) 时，UE 发送 AUTS 给网络
type AUTSHandler struct {
	// SQN 管理
	sqnManager *SQNManager
}

// SQNManager 管理序列号
type SQNManager struct {
	SQN   uint64 // 当前 SQN (48 位)
	SQNms uint64 // 最大接收的 SQN
	AMF   uint16 // 认证管理域
	Delta uint64 // 允许的差值
}

// NewSQNManager 创建 SQN 管理器
func NewSQNManager(initialSQN uint64) *SQNManager {
	return &SQNManager{
		SQN:   initialSQN,
		SQNms: initialSQN,
		AMF:   0x8000,  // 默认 AMF
		Delta: 1 << 28, // 允许较大的差值
	}
}

// VerifySQN 验证收到的 SQN
// 返回: true=SQN 有效, false=需要重同步
func (m *SQNManager) VerifySQN(receivedSQN uint64) bool {
	// RFC 3310: SQN 验证
	// 检查 SQN 是否在可接受范围内
	if receivedSQN > m.SQNms {
		// SQN 大于已知最大值，接受并更新
		m.SQNms = receivedSQN
		return true
	}

	// 检查是否在可接受的窗口内
	if m.SQNms-receivedSQN <= m.Delta {
		return true
	}

	// SQN 太旧或太新，需要重同步
	return false
}

// UpdateSQN 更新 SQN (成功认证后)
func (m *SQNManager) UpdateSQN(newSQN uint64) {
	if newSQN > m.SQN {
		m.SQN = newSQN
	}
	if newSQN > m.SQNms {
		m.SQNms = newSQN
	}
}

// GetSQN 返回当前 SQN
func (m *SQNManager) GetSQN() uint64 {
	return m.SQN
}

// EncodeSQN 将 SQN 编码为 6 字节
func EncodeSQN(sqn uint64) []byte {
	buf := make([]byte, 6)
	// SQN 是 48 位，存储在 6 字节中
	buf[0] = byte(sqn >> 40)
	buf[1] = byte(sqn >> 32)
	buf[2] = byte(sqn >> 24)
	buf[3] = byte(sqn >> 16)
	buf[4] = byte(sqn >> 8)
	buf[5] = byte(sqn)
	return buf
}

// DecodeSQN 从 6 字节解码 SQN
func DecodeSQN(data []byte) uint64 {
	if len(data) < 6 {
		return 0
	}
	return uint64(data[0])<<40 | uint64(data[1])<<32 |
		uint64(data[2])<<24 | uint64(data[3])<<16 |
		uint64(data[4])<<8 | uint64(data[5])
}

// ExtractSQNFromAUTN 从 AUTN 中提取 SQN
// AUTN = SQN⊕AK || AMF || MAC
func ExtractSQNFromAUTN(autn, ak []byte) (uint64, error) {
	if len(autn) < 6 || len(ak) < 6 {
		return 0, errors.New("AUTN 或 AK 长度不足")
	}

	// SQN = (SQN⊕AK) ⊕ AK
	sqnBytes := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqnBytes[i] = autn[i] ^ ak[i]
	}

	return DecodeSQN(sqnBytes), nil
}

// BuildAUTS 构建 AUTS 参数 (用于重同步)
// AUTS = SQN⊕AK_S || MAC_S
// 其中 AK_S 和 MAC_S 使用特殊的 f5* 和 f1* 函数计算
func BuildAUTS(sqn uint64, akStar, macS []byte) []byte {
	sqnBytes := EncodeSQN(sqn)

	// AUTS = (SQN ⊕ AK*) || MAC-S
	auts := make([]byte, 14) // 6 + 8 bytes

	// SQN ⊕ AK*
	for i := 0; i < 6; i++ {
		auts[i] = sqnBytes[i] ^ akStar[i]
	}

	// MAC-S (8 bytes)
	copy(auts[6:14], macS[:8])

	return auts
}

// BuildSyncFailureResponse 构建 EAP-AKA 同步失败响应
// Subtype: AKA-Synchronization-Failure (4)
// 包含 AT_AUTS 属性
func BuildSyncFailureResponse(eapID byte, auts []byte) []byte {
	// EAP 头部
	eapHeader := make([]byte, 8)
	eapHeader[0] = 2 // EAP Response
	eapHeader[1] = eapID
	// 长度在最后填充
	eapHeader[4] = 23 // EAP-AKA type
	eapHeader[5] = 4  // AKA-Synchronization-Failure subtype
	eapHeader[6] = 0  // Reserved
	eapHeader[7] = 0

	// AT_AUTS (Type=4, Length=4, 14 bytes AUTS + 2 bytes padding)
	atAuts := make([]byte, 20)
	atAuts[0] = 4 // AT_AUTS
	atAuts[1] = 5 // Length = 5 * 4 = 20 bytes
	atAuts[2] = 0 // Reserved
	atAuts[3] = 0
	copy(atAuts[4:18], auts)
	// 最后 2 字节是填充

	// 完整消息
	msg := append(eapHeader, atAuts...)

	// 填充长度
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg)))

	return msg
}

// 注意: AT_AUTS 已在 packet.go 中定义
