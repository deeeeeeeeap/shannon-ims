package swu

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
)

func (s *Session) ensureIKEDispatcher() {
	s.ikeMu.Lock()
	if s.ikeStarted {
		s.ikeMu.Unlock()
		return
	}
	s.ikeStarted = true
	s.ikeMu.Unlock()

	go s.ikeDispatchLoop()
}

func (s *Session) startIKEControlLoop() {
	s.ikeMu.Lock()
	s.ikeControlAlive = true
	s.ikeMu.Unlock()
	s.ensureIKEDispatcher()
}

func (s *Session) ikeDispatchLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case data, ok := <-s.socket.IKEPackets():
			if !ok {
				return
			}

			// 更新入站时间戳
			s.lastInboundTime = time.Now()

			hdr, err := ikev2.DecodeHeader(data)
			if err != nil {
				continue
			}

			if hdr.Flags&ikev2.FlagResponse != 0 {
				// 新机制：拦截包体交付给滑动窗口调度器
				if handled := s.taskMgr.HandleResponse(hdr.MessageID, data); handled {
					continue
				}

				// 旧机制保留用于支持零星写死的 ikeWaiters
				key := ikeWaitKey{exchangeType: hdr.ExchangeType, msgID: hdr.MessageID}
				s.ikeMu.Lock()
				ch := s.ikeWaiters[key]
				if ch == nil && s.ikePending != nil {
					s.ikePending[key] = data
				}
				s.ikeMu.Unlock()
				if ch != nil {
					select {
					case ch <- data:
					default:
					}
				}
				continue
			}

			// DPD 秒回短路：不排队，立即调用密码引擎和 Socket 返回 ePDG 存活证明
			if hdr.ExchangeType == ikev2.INFORMATIONAL {
				if hdr.NextPayload == ikev2.SK && (hdr.Flags&ikev2.FlagInitiator != 0) && hdr.Length == 76 { // AES/CBC+SHA256 等通常无额外载荷时的定长，或者解密探查
					// 为了 100% 安全，解密但不排队
					go func(msgID uint32, raw []byte) {
						s.Logger.Debug("涉嫌收到高优 DPD 探针，开启快速通道拦截检查", logger.Uint32("msgID", msgID))
						_, payloads, err := s.decryptAndParse(raw)
						if err == nil && len(payloads) == 0 {
							// 确认是空的 DPD 探针！秒回
							s.Logger.Info("收到 ePDG DPD 死亡探测信号，已进入特权通道优先确认存活", logger.Uint32("msgID", msgID))
							_ = s.sendEncryptedResponseWithMsgID(nil, ikev2.INFORMATIONAL, msgID)
							return
						}
						// 假如误判了有其他载荷，再送回原通道慢处理
						if err == nil {
							s.Logger.Debug("包含载荷，退回普通队列", logger.Int(" payloadCount", len(payloads)))
							s.handleIncomingInformational(raw)
						}
					}(hdr.MessageID, data)
					continue
				}
			}

			s.ikeMu.Lock()
			active := s.ikeControlAlive
			s.ikeMu.Unlock()
			if !active {
				continue
			}

			s.Logger.Debug("收到 ePDG 发起的请求",
				logger.Int("exchangeType", int(hdr.ExchangeType)),
				logger.Uint32("msgID", hdr.MessageID))

			switch hdr.ExchangeType {
			case ikev2.INFORMATIONAL:
				if err := s.handleIncomingInformational(data); err != nil {
					s.Logger.Warn("处理 INFORMATIONAL 失败", logger.Err(err))
				}
			case ikev2.CREATE_CHILD_SA:
				s.dispatchCreateChildSA(data)
			default:
				s.Logger.Warn("收到未知 Exchange Type",
					logger.Int("type", int(hdr.ExchangeType)))
			}
		}
	}
}

// dispatchCreateChildSA 解密 CREATE_CHILD_SA 并分发到 Child SA Rekey 或 IKE SA Rekey
func (s *Session) dispatchCreateChildSA(data []byte) {
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		s.Logger.Warn("解密 CREATE_CHILD_SA 失败", logger.Err(err))
		return
	}

	// 统一交给 handleIncomingCreateChildSAParsed 分发处理
	// 该函数会根据 ProtocolID 区分 Child SA Rekey 和 IKE SA Rekey
	s.Logger.Info("收到 CREATE_CHILD_SA 请求，开始处理",
		logger.Uint32("msgID", msgID))
	if err := s.handleIncomingCreateChildSAParsed(msgID, payloads); err != nil {
		s.Logger.Warn("处理 CREATE_CHILD_SA 失败", logger.Err(err))
	} else {
		s.Logger.Info("Child SA Rekey 处理完成")
	}
}

func (s *Session) sendEncryptedResponseWithMsgID(payloads []ikev2.Payload, exchangeType ikev2.ExchangeType, msgID uint32) error {
	packet, err := s.encryptAndWrapWithMsgID(payloads, exchangeType, msgID, true)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(packet)
}

func (s *Session) handleIncomingInformational(data []byte) error {
	msgID, payloads, err := s.decryptAndParse(data)
	if err != nil {
		return err
	}

	// 没有载荷 = DPD 请求，直接回复空 INFORMATIONAL
	if len(payloads) == 0 {
		s.Logger.Debug("收到对端 DPD 请求，回复空 INFORMATIONAL")
		return s.sendEncryptedResponseWithMsgID(nil, ikev2.INFORMATIONAL, msgID)
	}

	for _, pl := range payloads {
		if notify, ok := pl.(*ikev2.EncryptedPayloadNotify); ok {
			// RFC 6311: IKEV2_MESSAGE_ID_SYNC
			if notify.NotifyType == ikev2.IKEV2_MESSAGE_ID_SYNC {
				if len(notify.NotifyData) < 12 {
					s.Logger.Warn("IKEV2_MESSAGE_ID_SYNC 数据不足 12 字节",
						logger.Int("len", len(notify.NotifyData)))
					continue
				}
				// RFC 6311 §5.1: Notify Data = PENDING_NUM(4) + EXPECTED_SEND(4) + EXPECTED_RECV(4)
				// PENDING_NUM: 对端未响应的请求数量
				// EXPECTED_SEND: 对端下一个要发送的 Message ID
				// EXPECTED_RECV: 对端期望从我们收到的下一个 Message ID
				pendingNum := binary.BigEndian.Uint32(notify.NotifyData[0:4])
				expectedSend := binary.BigEndian.Uint32(notify.NotifyData[4:8])
				expectedRecv := binary.BigEndian.Uint32(notify.NotifyData[8:12])

				s.Logger.Info("收到 IKEV2_MESSAGE_ID_SYNC (RFC 6311)",
					logger.Uint32("pendingNum", pendingNum),
					logger.Uint32("expectedSend", expectedSend),
					logger.Uint32("expectedRecv", expectedRecv),
					logger.Uint32("currentSeqNum", s.SequenceNumber.Load()))

				// 更新本端 SequenceNumber：对端期望从我们收到的下一个 ID
				// 只允许向前调整（防止回退攻击）
				if expectedRecv > s.SequenceNumber.Load() {
					s.Logger.Info("MID Sync: 更新 SequenceNumber",
						logger.Uint32("old", s.SequenceNumber.Load()),
						logger.Uint32("new", expectedRecv))
					s.SequenceNumber.Store(expectedRecv)
				}

				// 回复 MID Sync 响应（RFC 6311 §5.2）
				// 响应中 Notify Data = EXPECTED_SEND(4) + EXPECTED_RECV(4)
				// 其中 EXPECTED_SEND = 我们下一个要发送的 MsgID (SequenceNumber)
				// EXPECTED_RECV = msgID + 1 (我们期望对端的下一个请求 ID)
				respData := make([]byte, 8)
				binary.BigEndian.PutUint32(respData[0:4], s.SequenceNumber.Load())
				binary.BigEndian.PutUint32(respData[4:8], msgID+1)
				syncResp := &ikev2.EncryptedPayloadNotify{
					ProtocolID: 0,
					NotifyType: ikev2.IKEV2_MESSAGE_ID_SYNC,
					NotifyData: respData,
				}
				return s.sendEncryptedResponseWithMsgID(
					[]ikev2.Payload{syncResp}, ikev2.INFORMATIONAL, msgID)
			}
			// RFC 4555: UPDATE_SA_ADDRESSES — ePDG 地址变更
			if notify.NotifyType == ikev2.UPDATE_SA_ADDRESSES {
				s.Logger.Info("收到 ePDG 发起的 UPDATE_SA_ADDRESSES (RFC 4555)")
				if s.mobikeSupported {
					// 用报文实际来源更新内核 SA/SP (参考 strongSwan ike_mobike.c:445-468)
					if s.xfrmMgr != nil {
						if sm, ok := s.socket.(*ipsec.SocketManager); ok {
							newRemoteIP := sm.RemoteIP()
							newLocalIP := sm.LocalIP()
							if newRemoteIP != nil && newLocalIP != nil {
								if err := s.updateXFRMState(newLocalIP.String(), newRemoteIP.String()); err != nil {
									s.Logger.Warn("UPDATE_SA_ADDRESSES: 更新 XFRM 失败", logger.Err(err))
								} else {
									s.Logger.Info("UPDATE_SA_ADDRESSES: XFRM 已更新",
										logger.String("localIP", newLocalIP.String()),
										logger.String("remoteIP", newRemoteIP.String()))
								}
							}
						}
					}
					// 提取请求中的 COOKIE2，并在响应中原样回传 (RFC 4555 §3.5)
					var respPayloads []ikev2.Payload
					for _, pl2 := range payloads {
						if n2, ok2 := pl2.(*ikev2.EncryptedPayloadNotify); ok2 {
							if n2.NotifyType == ikev2.COOKIE2 && len(n2.NotifyData) > 0 {
								respPayloads = append(respPayloads, &ikev2.EncryptedPayloadNotify{
									ProtocolID: 0,
									NotifyType: ikev2.COOKIE2,
									NotifyData: n2.NotifyData,
								})
								s.Logger.Debug("UPDATE_SA_ADDRESSES: 回传 COOKIE2")
							}
						}
					}
					return s.sendEncryptedResponseWithMsgID(respPayloads, ikev2.INFORMATIONAL, msgID)
				} else {
					s.Logger.Warn("收到 UPDATE_SA_ADDRESSES 但 MOBIKE 未协商")
				}
				continue
			}
			// RFC 5685: REDIRECT — 网关主动要求回弹重连
			if notify.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(notify.NotifyData)
				if err != nil {
					s.Logger.Warn("解析运行期 REDIRECT 负载失败", logger.Err(err))
				} else {
					s.Logger.Warn("收到 ePDG 下发的代理转移指令 (REDIRECT)，即将断开重连", logger.String("newAddr", addr))
					if s.OnRedirect != nil {
						go s.OnRedirect(addr)
					}
					if s.OnSessionDown != nil {
						go s.OnSessionDown()
					} else if s.cancel != nil {
						s.cancel()
					}
				}
				continue
			}
			continue // 其他未知 Notify 跳过
		}

		del, ok := pl.(*ikev2.EncryptedPayloadDelete)
		if !ok {
			continue
		}

		if del.ProtocolID == ikev2.ProtoIKE {
			s.Logger.Warn("收到 ePDG 发起的 IKE SA Delete，会话即将关闭")
			if s.OnSessionDown != nil {
				go s.OnSessionDown()
			} else if s.cancel != nil {
				s.cancel()
			}
			continue
		}

		if del.ProtocolID != ikev2.ProtoESP || del.SPISize != 4 {
			continue
		}

		// 收集需要回复的本端出站 SPI（对齐 strongSwan delete_child_sa 行为）
		var deletedLocalSPIs []uint32
		for i := 0; i+4 <= len(del.SPIs); i += 4 {
			spi := binary.BigEndian.Uint32(del.SPIs[i : i+4])
			s.Logger.Warn("收到 ePDG 发起的 Child SA Delete",
				logger.Uint32("spi", spi))
			// 查找对应本端出站 SPI 用于 Delete 确认
			if s.ChildSAOut != nil && s.ChildSAIn != nil && s.ChildSAIn.SPI == spi {
				deletedLocalSPIs = append(deletedLocalSPIs, s.ChildSAOut.SPI)
			}
			if s.ChildSAsIn != nil {
				delete(s.ChildSAsIn, spi)
			}
			if s.ChildSAOut != nil && s.ChildSAOut.SPI == spi {
				s.ChildSAOut = nil
				if len(s.childOutPolicies) > 0 {
					s.childOutPolicies[0].saOut = nil
				}
			}
		}

		// 回复 Delete 确认（包含本端出站 SPI）
		if len(deletedLocalSPIs) > 0 {
			raw := make([]byte, 0, 4*len(deletedLocalSPIs))
			for _, localSPI := range deletedLocalSPIs {
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, localSPI)
				raw = append(raw, b...)
			}
			delResp := &ikev2.EncryptedPayloadDelete{
				ProtocolID: ikev2.ProtoESP,
				SPISize:    4,
				NumSPIs:    uint16(len(deletedLocalSPIs)),
				SPIs:       raw,
			}
			return s.sendEncryptedResponseWithMsgID([]ikev2.Payload{delResp}, ikev2.INFORMATIONAL, msgID)
		}
	}

	return s.sendEncryptedResponseWithMsgID(nil, ikev2.INFORMATIONAL, msgID)
}

func (s *Session) handleIncomingCreateChildSAParsed(msgID uint32, payloads []ikev2.Payload) error {
	// Rekey Collision 检测：如果本端正在主动 Rekey（持有 rekeyMu），
	// 则回复 TEMPORARY_FAILURE 让 ePDG 稍后重试
	// 参考 strongSwan child_rekey.c 碰撞处理
	if !s.rekeyMu.TryLock() {
		s.Logger.Warn("检测到 Rekey 碰撞（本端正在 Rekey），响应 TEMPORARY_FAILURE",
			logger.Uint32("msgID", msgID))
		notify := &ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.TEMPORARY_FAILURE,
		}
		return s.sendEncryptedResponseWithMsgID([]ikev2.Payload{notify}, ikev2.CREATE_CHILD_SA, msgID)
	}
	defer s.rekeyMu.Unlock()

	var reqSA *ikev2.EncryptedPayloadSA
	var reqNonce []byte
	var peerSPI uint32
	var encrID uint16
	var protoID ikev2.ProtocolID
	var tsi []*ikev2.TrafficSelector
	var tsr []*ikev2.TrafficSelector

	for _, pl := range payloads {
		switch p := pl.(type) {
		case *ikev2.EncryptedPayloadSA:
			reqSA = p
			if len(p.Proposals) > 0 {
				protoID = p.Proposals[0].ProtocolID
				if len(p.Proposals[0].SPI) >= 4 {
					peerSPI = binary.BigEndian.Uint32(p.Proposals[0].SPI)
				}
				for _, t := range p.Proposals[0].Transforms {
					if t.Type == ikev2.TransformTypeEncr {
						encrID = uint16(t.ID)
					}
				}
			}
		case *ikev2.EncryptedPayloadNonce:
			reqNonce = p.NonceData
		case *ikev2.EncryptedPayloadTS:
			if p.IsInitiator {
				tsi = p.TrafficSelectors
			} else {
				tsr = p.TrafficSelectors
			}
		case *ikev2.EncryptedPayloadNotify:
			if p.NotifyType < 16384 {
				return fmt.Errorf("CREATE_CHILD_SA 错误通知: %d", p.NotifyType)
			}
		}
	}

	// 检查是否为 IKE SA Rekey (Proto = IKE)
	if protoID == ikev2.ProtoIKE {
		return s.HandleRekeyIKESARequest(msgID, payloads)
	}

	if reqSA == nil || len(reqNonce) == 0 || peerSPI == 0 || encrID == 0 {
		return fmt.Errorf("CREATE_CHILD_SA 请求缺少必要载荷")
	}

	nr, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	spiBytes, err := crypto.RandomBytes(4)
	if err != nil {
		return err
	}
	ourSPI := binary.BigEndian.Uint32(spiBytes)

	var encrKeyLenBits int
	for _, t := range reqSA.Proposals[0].Transforms {
		if t.Type == ikev2.TransformTypeEncr {
			for _, a := range t.Attributes {
				if a.Type == ikev2.AttributeKeyLength {
					encrKeyLenBits = int(a.Val)
				}
			}
		}
	}
	childEnc, err := crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("不支持的 Child SA 加密算法: %d", encrID)
	}
	keyLen := childEnc.KeySize()
	saltLen := 4
	keyMatLen := 2 * (keyLen + saltLen)

	seed := make([]byte, 0, len(reqNonce)+len(nr))
	seed = append(seed, reqNonce...)
	seed = append(seed, nr...)

	keyMat, err := crypto.PrfPlus(s.PRFAlg, s.Keys.SK_d, seed, keyMatLen)
	if err != nil {
		return err
	}

	outKey := keyMat[0 : keyLen+saltLen]
	inKey := keyMat[keyLen+saltLen : 2*(keyLen+saltLen)]

	outSA := ipsec.NewSecurityAssociation(ourSPI, childEnc, outKey, nil)
	outSA.RemoteSPI = peerSPI

	inSA := ipsec.NewSecurityAssociation(peerSPI, childEnc, inKey, nil)
	inSA.RemoteSPI = ourSPI

	// 保存旧 SPI 用于内核 SA 替换
	var oldOutSPI, oldInSPI uint32
	if s.ChildSAOut != nil {
		oldOutSPI = s.ChildSAOut.SPI
	}
	if s.ChildSAIn != nil {
		oldInSPI = s.ChildSAIn.SPI
	}

	// 替换主 SA 引用
	s.ChildSAOut = outSA
	s.ChildSAIn = inSA
	if s.ChildSAsIn != nil {
		s.ChildSAsIn[peerSPI] = inSA
	}

	if len(tsr) > 0 {
		if len(s.childOutPolicies) > 0 {
			s.childOutPolicies[0].saOut = outSA
		} else {
			s.childOutPolicies = append(s.childOutPolicies, childOutPolicy{saOut: outSA, tsr: tsr})
		}
	}

	if s.ws != nil {
		s.ws.LogChildSA(ourSPI, peerSPI, s.cfg.LocalAddr, s.cfg.EpDGAddr, inKey, outKey, encrID)
	}

	// 更新内核 XFRM SA（XFRMI 模式）
	if s.xfrmMgr != nil && oldOutSPI != 0 {
		if err := s.rekeyXFRMSA(oldOutSPI, oldInSPI, outSA, inSA, encrID, encrKeyLenBits); err != nil {
			s.Logger.Warn("对端 Rekey 后更新内核 XFRM SA 失败", logger.Err(err))
		}
	}

	s.Logger.Info("对端 CHILD_SA Rekey 成功",
		logger.Uint32("oldOutSPI", oldOutSPI),
		logger.Uint32("newOutSPI", ourSPI),
		logger.Uint32("peerSPI", peerSPI))

	// 被动 Rekey 成功后，重置冷却期和 Child Rekey Timer
	s.lastRekeyTime = time.Now()
	select {
	case s.childRekeyResetCh <- struct{}{}:
	default:
	}

	respProp := ikev2.NewProposal(1, ikev2.ProtoESP, spiBytes)
	respProp.AddTransform(ikev2.TransformTypeEncr, ikev2.AlgorithmType(encrID), 128)
	respProp.AddTransform(ikev2.TransformTypeESN, 0, 0)
	respSA := &ikev2.EncryptedPayloadSA{Proposals: []*ikev2.Proposal{respProp}}

	respNonce := &ikev2.EncryptedPayloadNonce{NonceData: nr}

	var respPayloads []ikev2.Payload
	respPayloads = append(respPayloads, respSA, respNonce)
	if len(tsi) > 0 {
		respPayloads = append(respPayloads, &ikev2.EncryptedPayloadTS{IsInitiator: true, TrafficSelectors: tsi})
	}
	if len(tsr) > 0 {
		respPayloads = append(respPayloads, &ikev2.EncryptedPayloadTS{IsInitiator: false, TrafficSelectors: tsr})
	}

	return s.sendEncryptedResponseWithMsgID(respPayloads, ikev2.CREATE_CHILD_SA, msgID)
}
