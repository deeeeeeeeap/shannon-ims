package swu

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// RekeyIKESA 执行 IKE SA 密钥轮换 (CREATE_CHILD_SA 交换, ProtocolID=IKE)
// RFC 7296 §2.8: 通过新 DH 交换刷新 IKE SA 的 SPIs、密钥和 MsgID
func (s *Session) RekeyIKESA() error {
	s.rekeyMu.Lock()
	defer s.rekeyMu.Unlock()

	if s.Keys == nil || len(s.Keys.SK_d) == 0 {
		return errors.New("IKE SA 未建立，无法 Rekey")
	}

	// 冷却期检查
	if !s.lastRekeyTime.IsZero() && time.Since(s.lastRekeyTime) < 30*time.Second {
		s.Logger.Debug("IKE Rekey 冷却期内，跳过",
			logger.Duration("sinceLast", time.Since(s.lastRekeyTime)))
		return nil
	}

	s.Logger.Info("开始 IKE SA Rekey")

	attempt, err := s.prepareIKERekeyRequest()
	if err != nil {
		return err
	}

	// 7. 保存旧密钥（用旧密钥发送请求和解密响应）
	oldSKd := make([]byte, len(s.Keys.SK_d))
	copy(oldSKd, s.Keys.SK_d)
	oldSPIi := s.SPIi
	oldSPIr := s.SPIr

	// 8. 发送 CREATE_CHILD_SA (ProtoIKE)
	respData, err := s.sendEncryptedWithRetry(attempt.payloads, ikev2.CREATE_CHILD_SA)
	if err != nil {
		return fmt.Errorf("IKE SA Rekey CREATE_CHILD_SA 发送失败: %v", err)
	}

	s.Logger.Info("IKE SA Rekey 收到响应", logger.Int("len", len(respData)))

	// 9. 处理响应
	return s.handleRekeyIKESAResp(respData, attempt.nonce, attempt.dh, attempt.spiI, oldSKd, oldSPIi, oldSPIr)
}

// handleRekeyIKESAResp 处理 IKE SA Rekey 的 CREATE_CHILD_SA 响应
func (s *Session) handleRekeyIKESAResp(
	data []byte,
	niNonce []byte,
	newDH *crypto.DiffieHellman,
	newSPIi uint64,
	oldSKd []byte,
	oldSPIi, oldSPIr uint64,
) error {
	// 用旧密钥解密
	_, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return fmt.Errorf("IKE SA Rekey 响应解密失败: %v", err)
	}

	// 提取 SA、KE、Nonce 载荷
	var newSPIr uint64
	var respSA *ikev2.EncryptedPayloadSA
	var respNonce []byte
	var respKE *ikev2.EncryptedPayloadKE

	for _, p := range payloads {
		switch pl := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			respSA = pl
			if len(pl.Proposals) > 0 && len(pl.Proposals[0].SPI) >= 8 {
				newSPIr = binary.BigEndian.Uint64(pl.Proposals[0].SPI[:8])
			}
			// 检查是否有错误通知
		case *ikev2.EncryptedPayloadNonce:
			respNonce = pl.NonceData
		case *ikev2.EncryptedPayloadKE:
			respKE = pl
		case *ikev2.EncryptedPayloadNotify:
			if pl.NotifyType < 16384 {
				return fmt.Errorf("IKE SA Rekey 被拒绝，通知类型: %d", pl.NotifyType)
			}
		}
	}

	if newSPIr == 0 {
		return errors.New("响应中未找到新 SPIr")
	}
	if len(respNonce) == 0 {
		return errors.New("响应中未找到 Nonce")
	}
	if respKE == nil || len(respKE.KEData) == 0 {
		return errors.New("响应中未找到 KE")
	}
	if err := validateIKERekeyResponseDH(newDH, respSA, respKE); err != nil {
		return err
	}

	// 计算新 DH 共享密钥
	if _, err := newDH.ComputeSharedSecret(respKE.KEData); err != nil {
		return fmt.Errorf("新 DH 计算失败: %v", err)
	}

	// 派生新 IKE SA 密钥
	// SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
	newKeys, err := s.GenerateIKESARekeyKeys(
		oldSKd, newDH.SharedKey,
		niNonce, respNonce,
		newSPIi, newSPIr,
	)
	if err != nil {
		return fmt.Errorf("IKE SA Rekey 密钥派生失败: %v", err)
	}

	// 用旧密钥发送 INFORMATIONAL DELETE 通知 ePDG 旧 IKE SA 废弃
	// 参考 strongSwan ike_rekey.c:727 — DELETE 必须在旧 SA 上发送，且需等待响应
	s.Logger.Debug("发送旧 IKE SA DELETE 通知（使用旧密钥）")
	del := &ikev2.EncryptedPayloadDelete{
		ProtocolID: ikev2.ProtoIKE,
		SPISize:    0,
		NumSPIs:    0,
		SPIs:       nil,
	}
	if _, err := s.sendEncryptedWithRetry([]ikev2.Payload{del}, ikev2.INFORMATIONAL); err != nil {
		s.Logger.Warn("发送旧 IKE SA DELETE 失败（继续切换）", logger.Err(err))
	} else {
		s.Logger.Info("旧 IKE SA DELETE 确认完成")
	}

	// 原子切换 IKE SA 状态（DELETE 发送后再切换）
	s.SPIi = newSPIi
	s.SPIr = newSPIr
	s.Keys = newKeys
	s.SequenceNumber.Store(0) // 新 IKE SA 的 MsgID 从 0 开始
	s.DH = newDH              // 更新 DH 状态

	s.Logger.Info("IKE SA Rekey 成功")

	// 更新冷却期时间戳
	s.lastRekeyTime = time.Now()

	// 通知 Timer 重置
	select {
	case s.rekeyResetCh <- struct{}{}:
	default:
	}

	return nil
}

// HandleRekeyIKESARequest 处理对端发起的 IKE SA Rekey 请求
func (s *Session) HandleRekeyIKESARequest(msgID uint32, payloads []ikev2.Payload) error {
	s.Logger.Info("收到 IKE SA Rekey 请求")

	var reqSA *ikev2.EncryptedPayloadSA
	var reqNonce []byte
	var reqKE *ikev2.EncryptedPayloadKE
	var peerSPI uint64

	for _, p := range payloads {
		switch pl := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			reqSA = pl
			if len(pl.Proposals) > 0 && len(pl.Proposals[0].SPI) >= 8 {
				peerSPI = binary.BigEndian.Uint64(pl.Proposals[0].SPI[:8])
			}
		case *ikev2.EncryptedPayloadNonce:
			reqNonce = pl.NonceData
		case *ikev2.EncryptedPayloadKE:
			reqKE = pl
		}
	}

	if reqSA == nil || len(reqNonce) == 0 || reqKE == nil || len(reqKE.KEData) == 0 || peerSPI == 0 {
		return errors.New("IKE SA Rekey 请求缺少必要载荷 (SA/KE/Nonce)")
	}

	// 1. 生成新 Nonce
	myNonce, err := crypto.RandomBytes(32)
	if err != nil {
		return fmt.Errorf("生成 Nonce 失败: %v", err)
	}

	// 2. 使用当前协商组验证 peer proposal/KE，并生成匹配的响应 DH。
	newDH, rekeyGroup, err := s.preparePeerIKERekeyDH(reqSA, reqKE)
	if err != nil {
		return err
	}

	// 4. 生成新 SPIr (本端)
	newSPIrBytes := make([]byte, 8)
	if _, err := rand.Read(newSPIrBytes); err != nil {
		return fmt.Errorf("生成 SPIr 失败: %v", err)
	}
	newSPIr := binary.BigEndian.Uint64(newSPIrBytes)

	// 5. 构建响应载荷
	// SA Payload (ProtoIKE, SPI = newSPIr)
	// 简化：直接接受对方提议的算法（假设是常用的且我们支持）
	// 严格来说应该 match proposal，这里直接构造一个匹配的响应
	proposal := reqSA.Proposals[0]
	respProp := ikev2.NewProposal(proposal.ProposalNum, ikev2.ProtoIKE, newSPIrBytes)
	for _, t := range proposal.Transforms {
		respProp.AddTransform(t.Type, ikev2.AlgorithmType(t.ID), 0) // KeyLen 简化处理
	}

	respSA := &ikev2.EncryptedPayloadSA{
		Proposals: []*ikev2.Proposal{respProp},
	}

	respKEPayload := &ikev2.EncryptedPayloadKE{
		DHGroup: rekeyGroup,
		KEData:  newDH.PublicKeyBytes(),
	}

	respNoncePayload := &ikev2.EncryptedPayloadNonce{NonceData: myNonce}

	// 6. 发送响应 (使用旧密钥加密)
	respPayloads := []ikev2.Payload{respSA, respNoncePayload, respKEPayload}
	// 注意：sendEncryptedResponseWithMsgID 使用当前（旧）密钥加密
	if err := s.sendEncryptedResponseWithMsgID(respPayloads, ikev2.CREATE_CHILD_SA, msgID); err != nil {
		return fmt.Errorf("发送 IKE SA Rekey 响应失败: %v", err)
	}

	s.Logger.Info("IKE SA Rekey 响应已发送")

	// 7. 派生新密钥
	// SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
	// Ni = reqNonce, Nr = myNonce
	// SPIi = peerSPI (对方是 Initiator), SPIr = newSPIr (我是 Responder)
	oldSKd := make([]byte, len(s.Keys.SK_d))
	copy(oldSKd, s.Keys.SK_d)

	newKeys, err := s.GenerateIKESARekeyKeys(
		oldSKd, newDH.SharedKey,
		reqNonce, myNonce,
		peerSPI, newSPIr,
	)
	if err != nil {
		return fmt.Errorf("新 IKE SA 密钥派生失败: %v", err)
	}

	// 8. 切换密钥
	s.rekeyMu.Lock()
	s.SPIi = peerSPI
	s.SPIr = newSPIr
	s.Keys = newKeys
	s.SequenceNumber.Store(0)
	s.DH = newDH
	s.lastRekeyTime = time.Now()
	s.rekeyMu.Unlock()

	s.Logger.Info("被动 IKE SA Rekey 完成，密钥已更新")

	// 通知 Timer 重置 (防止我们紧接着又发起 Rekey)
	select {
	case s.rekeyResetCh <- struct{}{}:
	default:
	}

	return nil
}
