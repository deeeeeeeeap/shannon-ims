package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// RFC 7383: IKE Fragmentation
// SKF (Encrypted Fragment Payload) 头部格式:
//   Fragment Number (2 bytes) | Total Fragments (2 bytes) | IV + Ciphertext + ICV

const (
	// 默认 IKE 分片 MTU (去掉 IP/UDP/IKE 开销后的单个分片最大载荷大小)
	// IKE Header = 28, SKF Header = 8 (Generic Header 4 + Fragment 4), IP = 20, UDP = 8
	// 1280 - 20 - 8 - 28 - 8 = 1216 字节可用于 IV + 密文 + ICV
	defaultFragmentMTU = 1280
	ikeOverhead        = 28 + 8 + 20 + 8 // IKE Header + SKF Header + IP + UDP
	maxFragments       = 255             // RFC 7383: 最多 255 个分片
	// 最大重组后包大小 (防止内存耗尽攻击)
	// 参考 strongSwan: frag->max_packet 默认 64KB
	maxFragmentedPacket = 64 * 1024
)

// fragmentBuffer 缓存接收端的分片，按 Message ID 分组
type fragmentBuffer struct {
	mu    sync.Mutex
	frags map[uint32]*fragmentSet
}

// fragmentSet 单个 Message ID 的所有分片
type fragmentSet struct {
	total    uint16
	received map[uint16][]byte // Fragment Number → 解密后的明文
	totalLen int               // 所有已接收分片的总字节数
}

func newFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{
		frags: make(map[uint32]*fragmentSet),
	}
}

// addFragment 添加一个分片，返回是否已收齐所有分片
// 参考 strongSwan message.c:add_fragment() 的安全检查:
//   - 重复分片检测 (忽略已有分片)
//   - 最大包大小限制 (防止 DoS)
//   - 总数不一致时重置缓存
func (fb *fragmentBuffer) addFragment(msgID uint32, fragNum, totalFrags uint16, plaintext []byte) (bool, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	fs, ok := fb.frags[msgID]
	if !ok {
		fs = &fragmentSet{
			total:    totalFrags,
			received: make(map[uint16][]byte),
		}
		fb.frags[msgID] = fs
	}

	// strongSwan: 如果总数变大，重置缓存 (可能是对端重发了不同分片)
	if totalFrags > fs.total {
		fs.total = totalFrags
		fs.received = make(map[uint16][]byte)
		fs.totalLen = 0
	} else if fs.total != totalFrags {
		return false, fmt.Errorf("分片总数不一致: 期望 %d, 收到 %d", fs.total, totalFrags)
	}

	// strongSwan: 忽略重复分片
	if _, exists := fs.received[fragNum]; exists {
		return false, nil
	}

	// strongSwan: 检查最大包大小 (防止内存耗尽攻击)
	fs.totalLen += len(plaintext)
	if fs.totalLen > maxFragmentedPacket {
		delete(fb.frags, msgID)
		return false, fmt.Errorf("分片重组后超过最大包大小限制 (%d > %d)", fs.totalLen, maxFragmentedPacket)
	}

	fs.received[fragNum] = plaintext
	return uint16(len(fs.received)) == fs.total, nil
}

// reassemble 按 Fragment Number 顺序拼接所有分片的明文
func (fb *fragmentBuffer) reassemble(msgID uint32) ([]byte, error) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	fs, ok := fb.frags[msgID]
	if !ok {
		return nil, errors.New("未找到分片数据")
	}

	var result []byte
	for i := uint16(1); i <= fs.total; i++ {
		data, ok := fs.received[i]
		if !ok {
			return nil, fmt.Errorf("缺少分片 %d/%d", i, fs.total)
		}
		result = append(result, data...)
	}

	// 清理缓存
	delete(fb.frags, msgID)
	return result, nil
}

// fragmentMessage 将 IKE 消息分片发送 (RFC 7383)
// plainInner: 加密前的内部载荷数据 (已序列化的载荷链)
// 返回多个 SKF 数据包
func (s *Session) fragmentMessage(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType) ([][]byte, error) {
	// 序列化所有载荷
	innerData := []byte{}
	for i, pl := range payloads {
		nextType := ikev2.NoNextPayload
		if i < len(payloads)-1 {
			nextType = payloads[i+1].Type()
		}
		body, err := pl.Encode()
		if err != nil {
			return nil, err
		}
		header := &ikev2.PayloadHeader{
			NextPayload:   nextType,
			PayloadLength: uint16(4 + len(body)),
		}
		innerData = append(innerData, header.Encode()...)
		innerData = append(innerData, body...)
	}

	// 计算每个分片可承载的明文大小
	ivSize := s.EncAlg.IVSize()
	icvSize := 0
	if s.ikeIsAEAD {
		icvSize = 16 // GCM ICV
	} else if s.IntegAlg != nil {
		icvSize = s.IntegAlg.OutputSize()
	}

	// 可用空间 = MTU - IKE Header - SKF Header(4+4) - IV - ICV
	fragMTU := int(s.ikeFragmentMTU)
	maxPlaintextPerFrag := fragMTU - ikeOverhead - ivSize - icvSize
	if s.ikeIsAEAD {
		maxPlaintextPerFrag-- // Pad Length
	}

	// 对 CBC 模式需要考虑 padding
	blockSize := s.EncAlg.BlockSize()
	if !s.ikeIsAEAD && blockSize > 0 {
		// 留出 padding 空间 (最多 blockSize 字节)
		maxPlaintextPerFrag -= blockSize
	}
	if maxPlaintextPerFrag <= 0 {
		return nil, errors.New("分片 MTU 太小")
	}

	// 计算分片数
	numFrags := (len(innerData) + maxPlaintextPerFrag - 1) / maxPlaintextPerFrag
	if numFrags > maxFragments {
		return nil, fmt.Errorf("分片数超限: %d > %d", numFrags, maxFragments)
	}
	if numFrags <= 1 {
		// 不需要分片
		return nil, nil
	}

	// 所有分片共享同一个 Message ID
	msgID := uint32(s.NextSequenceNumber())

	// 第一个分片的 NextPayload = 第一个载荷的类型（告诉接收方重组后的第一个载荷类型）
	firstPayloadType := ikev2.NoNextPayload
	if len(payloads) > 0 {
		firstPayloadType = payloads[0].Type()
	}

	var packets [][]byte
	for i := 0; i < numFrags; i++ {
		start := i * maxPlaintextPerFrag
		end := start + maxPlaintextPerFrag
		if end > len(innerData) {
			end = len(innerData)
		}
		chunk := innerData[start:end]

		// 构建 SKF 载荷
		fragData, err := s.buildSKFPacket(chunk, uint16(i+1), uint16(numFrags), msgID, exchangeType, firstPayloadType)
		if err != nil {
			return nil, fmt.Errorf("构建分片 %d/%d 失败: %v", i+1, numFrags, err)
		}
		packets = append(packets, fragData)
	}

	s.Logger.Debug("IKE 消息已分片",
		logger.Int("fragments", numFrags),
		logger.Int("totalSize", len(innerData)))
	return packets, nil
}

// buildSKFPacket 构建单个 SKF (Encrypted Fragment) 数据包
func (s *Session) buildSKFPacket(plaintext []byte, fragNum, totalFrags uint16, msgID uint32, exchangeType ikev2.ExchangeType, firstPayloadType ikev2.PayloadType) ([]byte, error) {
	key := s.Keys.SK_ei
	iv, err := crypto.RandomBytes(s.EncAlg.IVSize())
	if err != nil {
		return nil, err
	}

	icvSize := 0
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize = s.IntegAlg.OutputSize()
	}

	// 加密明文
	plainToEncrypt := plaintext
	expectedCipherLen := len(plainToEncrypt)
	if s.ikeIsAEAD {
		plainToEncrypt = append(append([]byte(nil), plainToEncrypt...), 0)
		expectedCipherLen = len(plainToEncrypt) + 16 // GCM tag
	} else {
		blockSize := s.EncAlg.BlockSize()
		if blockSize > 0 {
			padLen := 0
			if rem := (len(plainToEncrypt) + 1) % blockSize; rem != 0 {
				padLen = blockSize - rem
			}
			plainToEncrypt = append(plainToEncrypt, make([]byte, padLen)...)
			plainToEncrypt = append(plainToEncrypt, byte(padLen))
			expectedCipherLen = len(plainToEncrypt)
		}
	}

	// Fragment Header: Fragment Number (2) + Total Fragments (2)
	fragHeader := make([]byte, 4)
	binary.BigEndian.PutUint16(fragHeader[0:2], fragNum)
	binary.BigEndian.PutUint16(fragHeader[2:4], totalFrags)

	// SKF 载荷: Generic Header (4) + Fragment Header (4) + IV + Ciphertext + ICV
	skfPayloadLen := uint16(4 + 4 + len(iv) + expectedCipherLen + icvSize)

	// 只有第一个分片才指定 NextPayload (告诉对端重组后的第一个内部载荷类型)
	nextPayload := ikev2.NoNextPayload
	if fragNum == 1 {
		nextPayload = firstPayloadType
	}

	// IKE Header
	hdr := &ikev2.IKEHeader{
		SPIi:         s.SPIi,
		SPIr:         s.SPIr,
		NextPayload:  ikev2.EncryptedFragment, // 53
		Version:      0x20,
		ExchangeType: exchangeType,
		Flags:        ikev2.FlagInitiator,
		MessageID:    msgID,
		Length:       uint32(ikev2.IKE_HEADER_LEN) + uint32(skfPayloadLen),
	}
	ikeHeader := hdr.Encode()
	skfGenHeader := (&ikev2.PayloadHeader{
		NextPayload:   nextPayload,
		PayloadLength: skfPayloadLen,
	}).Encode()
	aad := make([]byte, 0, len(ikeHeader)+len(skfGenHeader)+len(fragHeader))
	aad = append(aad, ikeHeader...)
	aad = append(aad, skfGenHeader...)
	aad = append(aad, fragHeader...)

	// 加密
	ciphertext, err := s.EncAlg.Encrypt(plainToEncrypt, key, iv, aad)
	if err != nil {
		return nil, err
	}

	// 组装数据包
	packet := append([]byte(nil), aad...)
	packet = append(packet, iv...)
	packet = append(packet, ciphertext...)
	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icv := s.IntegAlg.Compute(s.Keys.SK_ai, packet)
		packet = append(packet, icv...)
	}

	return packet, nil
}

// decryptSKF 解密单个 SKF 载荷，返回明文、Fragment Number、Total Fragments
func (s *Session) decryptSKF(data []byte) (plaintext []byte, fragNum, totalFrags uint16, msgID uint32, err error) {
	header, err := ikev2.DecodeHeader(data)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	msgID = header.MessageID

	offset := ikev2.IKE_HEADER_LEN

	// SKF Generic Header (4 bytes)
	if offset+4 > len(data) {
		return nil, 0, 0, 0, errors.New("SKF 数据太短 (generic header)")
	}
	genHeader, err := ikev2.DecodePayloadHeader(data[offset : offset+4])
	if err != nil {
		return nil, 0, 0, 0, err
	}
	_ = genHeader
	offset += 4

	// Fragment Header (4 bytes)
	if offset+4 > len(data) {
		return nil, 0, 0, 0, errors.New("SKF 数据太短 (fragment header)")
	}
	fragNum = binary.BigEndian.Uint16(data[offset : offset+2])
	totalFrags = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	offset += 4
	aadEnd := offset

	// IV
	ivSize := s.EncAlg.IVSize()
	if offset+ivSize > len(data) {
		return nil, 0, 0, 0, errors.New("SKF 数据太短 (IV)")
	}
	iv := data[offset : offset+ivSize]
	offset += ivSize

	// Ciphertext + ICV
	aad := data[:aadEnd]
	key := s.Keys.SK_er
	ciphertext := data[offset:]

	if !s.ikeIsAEAD && s.IntegAlg != nil {
		icvSize := s.IntegAlg.OutputSize()
		if len(ciphertext) < icvSize {
			return nil, 0, 0, 0, errors.New("SKF 数据太短 (ICV)")
		}
		receivedICV := ciphertext[len(ciphertext)-icvSize:]
		ciphertext = ciphertext[:len(ciphertext)-icvSize]

		// 完整性校验范围: IKE Header + Generic Header + Fragment Header + IV + Ciphertext
		dataToVerify := data[:ikev2.IKE_HEADER_LEN+4+4+ivSize+len(ciphertext)]
		if !s.IntegAlg.Verify(s.Keys.SK_ar, dataToVerify, receivedICV) {
			return nil, 0, 0, 0, errors.New("SKF 完整性校验失败")
		}
	}

	plaintext, err = s.EncAlg.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("SKF 解密失败: %v", err)
	}

	if len(plaintext) < 1 {
		return nil, 0, 0, 0, errors.New("SKF 明文太短")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if len(plaintext) < 1+padLen {
		return nil, 0, 0, 0, errors.New("SKF 填充长度无效")
	}
	plaintext = plaintext[:len(plaintext)-1-padLen]

	return plaintext, fragNum, totalFrags, msgID, nil
}

// shouldFragment 判断载荷是否需要分片
func (s *Session) shouldFragment(payloads []ikev2.Payload) bool {
	if !s.fragmentationSupported {
		return false
	}

	// 估算总大小
	totalSize := ikev2.IKE_HEADER_LEN + 4 // IKE Header + SK Header
	totalSize += s.EncAlg.IVSize()
	for _, pl := range payloads {
		body, err := pl.Encode()
		if err != nil {
			return false
		}
		totalSize += 4 + len(body) // Payload Header + Body
	}

	if !s.ikeIsAEAD && s.IntegAlg != nil {
		totalSize += s.IntegAlg.OutputSize()
	} else if s.ikeIsAEAD {
		totalSize += 1 + 16 // Pad Length + GCM tag
	}

	return totalSize > int(s.ikeFragmentMTU)
}
