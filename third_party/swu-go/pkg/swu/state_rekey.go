package swu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
)

// RekeyChildSA 执行 CHILD_SA 密钥轮换 (CREATE_CHILD_SA 交换)
// RFC 7296 1.3.3: 重新协商 CHILD_SA
func (s *Session) RekeyChildSA() error {
	// 防止并发 rekey（两个 SPI 的 expire 会同时触发）
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()

	if s.ChildSAOut == nil {
		return errors.New("没有活动的 CHILD_SA 可以 Rekey")
	}

	// 冷却期去重（在 mutex 内检查，确保第二个 goroutine 能看到最新的 lastRekeyTime）
	if !s.lastRekeyTime.IsZero() && time.Since(s.lastRekeyTime) < 30*time.Second {
		s.Logger.Debug("Rekey 冷却期内，跳过重复 Rekey",
			logger.Duration("sinceLast", time.Since(s.lastRekeyTime)))
		return nil
	}

	s.Logger.Info("开始 CHILD_SA Rekey")

	// 1. 生成新的 Nonce
	newNonce, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}

	// 2. 生成新的 SPI
	newSPI, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	newSPIValue := binary.BigEndian.Uint32(newSPI)

	// 3. 构造 SA 载荷（与 IKE_AUTH 时一致，提供 CBC 和 GCM 两个选择）
	propCBC := ikev2.NewProposal(1, ikev2.ProtoESP, newSPI)
	propCBC.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_CBC, 128)
	propCBC.AddTransform(ikev2.TransformTypeInteg, ikev2.AUTH_HMAC_SHA2_256_128, 0)
	if s.cfg.EnableESN {
		propCBC.AddTransform(ikev2.TransformTypeESN, 1, 0) // ESN
	}
	propCBC.AddTransform(ikev2.TransformTypeESN, 0, 0) // NO_ESN (fallback)

	propGCM := ikev2.NewProposal(2, ikev2.ProtoESP, newSPI)
	propGCM.AddTransformWithKeyLen(ikev2.TransformTypeEncr, ikev2.ENCR_AES_GCM_16, 128)
	if s.cfg.EnableESN {
		propGCM.AddTransform(ikev2.TransformTypeESN, 1, 0) // ESN
	}
	propGCM.AddTransform(ikev2.TransformTypeESN, 0, 0) // NO_ESN (fallback)

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{propCBC, propGCM},
	}

	// 4. Nonce 载荷
	noncePayload := &ikev2.EncryptedPayloadNonce{NonceData: newNonce}

	// 5. REKEY_SA Notify (告知要 Rekey 哪个 SA)
	oldSPIBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(oldSPIBytes, s.ChildSAOut.SPI)
	rekeyNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: ikev2.ProtoESP,
		SPI:        oldSPIBytes,
		NotifyType: ikev2.REKEY_SA,
	}

	// 6. TSi / TSr (保持不变，使用全流量)
	tsi := s.tsi
	tsr := s.tsr
	if len(tsi) == 0 || len(tsr) == 0 {
		ts := ikev2.NewTrafficSelectorIPV4(
			[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255},
			0, 65535,
		)
		tsi = []*ikev2.TrafficSelector{ts}
		tsr = []*ikev2.TrafficSelector{ts}
	}
	tsPayloadI := &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: tsi}
	tsPayloadR := &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: tsr}

	// 7. 构造并发送 CREATE_CHILD_SA 请求
	payloads := []ikev2.Payload{saPayload, noncePayload, rekeyNotify, tsPayloadI, tsPayloadR}
	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.CREATE_CHILD_SA)
	if err != nil {
		return fmt.Errorf("CREATE_CHILD_SA 失败: %v", err)
	}

	s.Logger.Info("Rekey 收到 ePDG 响应", logger.Int("len", len(respData)))
	return s.handleCreateChildSAResp(respData, newNonce, newSPIValue)
}

// handleCreateChildSAResp 处理 CREATE_CHILD_SA 响应
func (s *Session) handleCreateChildSAResp(data []byte, niNonce []byte, newSPI uint32) error {
	s.Logger.Debug("开始解密 Rekey 响应", logger.Int("dataLen", len(data)))
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		s.Logger.Warn("Rekey 响应解密失败", logger.Err(err))
		return err
	}

	s.Logger.Info("Rekey 响应解密成功", logger.Int("payloadCount", len(payloads)))
	for i, pl := range payloads {
		s.Logger.Debug("Rekey 响应载荷",
			logger.Int("index", i),
			logger.String("type", fmt.Sprintf("%T", pl)))
	}

	var respSA *ikev2.EncryptedPayloadSA
	var respNonce []byte
	var respSPI uint32
	var encrID uint16
	var integID uint16
	var encrKeyLenBits int

	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			respSA = p
			if len(p.Proposals) > 0 && len(p.Proposals[0].SPI) >= 4 {
				respSPI = binary.BigEndian.Uint32(p.Proposals[0].SPI)
			}
			if len(p.Proposals) > 0 {
				for _, t := range p.Proposals[0].Transforms {
					switch t.Type {
					case ikev2.TransformTypeEncr:
						encrID = uint16(t.ID)
						for _, a := range t.Attributes {
							if a.Type == ikev2.AttributeKeyLength {
								encrKeyLenBits = int(a.Val)
							}
						}
					case ikev2.TransformTypeInteg:
						integID = uint16(t.ID)
					}
				}
			}
		case *ikev2.EncryptedPayloadNonce:
			respNonce = p.NonceData
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 { // 错误通知
				return fmt.Errorf("CREATE_CHILD_SA 被拒绝，通知类型: %d", p.NotifyType)
			}
		}
	}

	if respSA == nil || respNonce == nil {
		return errors.New("CREATE_CHILD_SA 响应缺少必要的载荷")
	}
	if encrID == 0 {
		return errors.New("CREATE_CHILD_SA 响应缺少加密算法选择")
	}

	// 密钥派生（与 state_auth.go 一致）
	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}

	isAEAD := encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	encKeyLen := childEnc.KeySize()
	saltLen := 0
	integKeyLen := 0
	var integAlg crypto.IntegrityAlgorithm

	if isAEAD {
		saltLen = 4
	} else {
		integAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("不支持的 Child SA 完整性算法: %d", integID)
		}
		integKeyLen = integAlg.KeySize()
	}

	keyMatLen := 2 * (encKeyLen + saltLen + integKeyLen)
	seed := make([]byte, 0, len(niNonce)+len(respNonce))
	seed = append(seed, niNonce...)
	seed = append(seed, respNonce...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	// 按 RFC 7296 顺序切分密钥材料
	cursor := 0
	outEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	outIntegKey := []byte(nil)
	if !isAEAD {
		outIntegKey = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}
	inEncKey := keyMat[cursor : cursor+encKeyLen+saltLen]
	cursor += encKeyLen + saltLen
	inIntegKey := []byte(nil)
	if !isAEAD {
		inIntegKey = keyMat[cursor : cursor+integKeyLen]
	}

	// 构造新 SA
	// 注意 SPI 约定（与 state_auth.go 一致）：
	// - ChildSAOut.SPI = respSPI (ePDG 分配，用于出站 ESP 包头)
	// - ChildSAIn.SPI  = newSPI  (本端生成，ePDG 用于发给我们的 ESP 包头)
	var newSAOut, newSAIn *ipsec.SecurityAssociation
	if isAEAD {
		newSAOut = ipsec.NewSecurityAssociation(respSPI, childEnc, outEncKey, nil)
		newSAIn = ipsec.NewSecurityAssociation(newSPI, childEnc, inEncKey, nil)
	} else {
		newSAOut = ipsec.NewSecurityAssociationCBC(respSPI, childEnc, outEncKey, integAlg, outIntegKey)
		newSAIn = ipsec.NewSecurityAssociationCBC(newSPI, childEnc, inEncKey, integAlg, inIntegKey)
	}
	newSAOut.RemoteSPI = newSPI
	newSAIn.RemoteSPI = respSPI

	// 替换内存中的旧 SA
	oldOutSPI := s.ChildSAOut.SPI
	oldInSPI := s.ChildSAIn.SPI
	s.ChildSAOut = newSAOut
	s.ChildSAIn = newSAIn
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[newSPI] = newSAIn
	}
	if len(s.childOutPolicies) > 0 {
		s.childOutPolicies[0].saOut = newSAOut
	} else if len(s.tsr) > 0 {
		s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: newSAOut, tsr: s.tsr})
	}
	if s.ws != nil {
		s.ws.LogChildSA(newSPI, respSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inEncKey, outEncKey, encrID)
	}

	// 更新内核 XFRM SA（XFRMI 模式）
	if s.xfrmMgr != nil {
		if err := s.rekeyXFRMSA(oldOutSPI, oldInSPI, newSAOut, newSAIn, encrID, encrKeyLenBits); err != nil {
			s.Logger.Warn("Rekey 后更新内核 XFRM SA 失败", logger.Err(err))
		}
	}

	s.Logger.Info("CHILD_SA Rekey 成功", logger.Uint32("oldSPI", oldOutSPI), logger.Uint32("newSPI", newSPI))

	// 更新冷却期时间戳（防止另一个 SPI 的 Soft Expire 再次触发 rekey）
	s.lastRekeyTime = time.Now()

	// 通知 Timer 重置（非阻塞写入）
	select {
	case s.rekeyResetCh <- struct{}{}:
	default:
	}

	// 同步发送删除旧 SA 的通知（不用 goroutine，避免 msgID 竞争）
	if err := s.sendDeleteChildSA([]uint32{oldOutSPI}); err != nil {
		s.Logger.Warn("发送旧 Child SA Delete 通知失败", logger.Err(err))
	}

	return nil
}
