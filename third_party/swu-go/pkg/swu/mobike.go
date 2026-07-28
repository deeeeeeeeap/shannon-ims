package swu

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/1239t/swu-go/pkg/driver"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
	"github.com/iniwex5/netlink"
)

const cookie2Size = 16

// UpdateAddresses 执行 MOBIKE 地址更新 (RFC 4555)
// 操作顺序参考 strongSwan ike_mobike.c:
//  1. 先发送 UPDATE_SA_ADDRESSES + COOKIE2 + NAT_DETECTION
//  2. 验证响应中的 COOKIE2
//  3. 确认成功后才更新 Socket 和 XFRM
func (s *Session) UpdateAddresses(newLocalAddr, newRemoteAddr string) error {
	if !s.mobikeSupported {
		return errors.New("对端不支持 MOBIKE，无法动态更新地址")
	}

	s.Logger.Info("开始 MOBIKE 地址更新",
		logger.String("newLocal", newLocalAddr),
		logger.String("newRemote", newRemoteAddr))

	// ── 步骤 1: 发送 UPDATE_SA_ADDRESSES + COOKIE2 + NAT Detection ──
	cookie2, err := s.sendMOBIKEUpdate()
	if err != nil {
		return fmt.Errorf("MOBIKE 通知发送失败: %v", err)
	}
	_ = cookie2 // COOKIE2 验证在 sendMOBIKEUpdate 内部完成

	// ── 步骤 2: 确认成功后，切换 Socket ──
	s.ikeMu.Lock()
	defer s.ikeMu.Unlock()

	s.cfg.EpDGAddr = newRemoteAddr

	localPort := s.cfg.LocalPort
	localBind := fmt.Sprintf("%s:%d", newLocalAddr, localPort)
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 4500
	}
	remoteBind := fmt.Sprintf("%s:%d", newRemoteAddr, remotePort)

	var newSocket Transport
	if s.cfg.TransportFactory != nil {
		newSocket, err = s.cfg.TransportFactory(localBind, remoteBind)
	} else {
		newSocket, err = ipsec.NewSocketManager(localBind, remoteBind, s.cfg.DNSServer)
	}
	if err != nil {
		return fmt.Errorf("绑定新 Socket 失败: %v", err)
	}
	newSocket.Start()

	oldSocket := s.socket
	s.socket = newSocket
	if oldSocket != nil {
		oldSocket.Stop()
	}

	// ── 步骤 3: 更新内核 XFRM SA 和 SP ──
	if s.xfrmMgr != nil {
		if err := s.updateXFRMState(newLocalAddr, newRemoteAddr); err != nil {
			s.Logger.Warn("MOBIKE: 更新 XFRM 失败", logger.Err(err))
		}
	}

	s.Logger.Info("MOBIKE 地址更新完成")
	return nil
}

// sendMOBIKEUpdate 发送 UPDATE_SA_ADDRESSES + COOKIE2 + NAT Detection，
// 并验证响应中的 COOKIE2 (RFC 4555 §3.5)
func (s *Session) sendMOBIKEUpdate() ([]byte, error) {
	// 生成 COOKIE2 (16 字节随机)
	cookie2 := make([]byte, cookie2Size)
	if _, err := rand.Read(cookie2); err != nil {
		return nil, fmt.Errorf("生成 COOKIE2 失败: %v", err)
	}

	// 构建载荷
	payloads := []ikev2.Payload{
		// UPDATE_SA_ADDRESSES
		&ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.UPDATE_SA_ADDRESSES,
		},
		// COOKIE2
		&ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.COOKIE2,
			NotifyData: cookie2,
		},
	}

	// NAT Detection 载荷 (RFC 4555 §3.5 强制要求)
	if sm, ok := s.socket.(*ipsec.SocketManager); ok {
		localIP := sm.LocalIP()
		remoteIP := sm.RemoteIP()
		localPort := sm.LocalPort()
		remotePort := uint16(sm.RemotePort())
		if localIP != nil && remoteIP != nil {
			srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
			dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)
			payloads = append(payloads,
				ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash),
				ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash),
			)
		}
	}

	// 发送 INFORMATIONAL 并等待响应
	respData, err := s.sendEncryptedWithRetry(payloads, ikev2.INFORMATIONAL)
	if err != nil {
		return nil, err
	}

	// 验证响应中的 COOKIE2
	if err := s.verifyCookie2Response(respData, cookie2); err != nil {
		return nil, err
	}

	return cookie2, nil
}

// verifyCookie2Response 解析响应并验证 COOKIE2 一致性
func (s *Session) verifyCookie2Response(respData []byte, expectedCookie2 []byte) error {
	if len(respData) == 0 {
		// 空响应 = 对端不支持 COOKIE2，接受
		s.Logger.Debug("MOBIKE 响应为空（无 COOKIE2）")
		return nil
	}

	_, respPayloads, err := s.decryptAndParse(respData)
	if err != nil {
		return fmt.Errorf("解析 MOBIKE 响应失败: %v", err)
	}

	for _, pl := range respPayloads {
		if notify, ok := pl.(*ikev2.EncryptedPayloadNotify); ok {
			if notify.NotifyType == ikev2.COOKIE2 {
				if len(notify.NotifyData) != len(expectedCookie2) {
					return errors.New("COOKIE2 长度不匹配，关闭连接")
				}
				for i := range expectedCookie2 {
					if notify.NotifyData[i] != expectedCookie2[i] {
						return errors.New("COOKIE2 验证失败，可能遭受攻击")
					}
				}
				s.Logger.Debug("COOKIE2 验证通过")
				return nil
			}
		}
	}
	// 响应中没有 COOKIE2 — 对端不支持，接受
	s.Logger.Debug("MOBIKE 响应中无 COOKIE2")
	return nil
}

// updateXFRMState 使用新地址更新所有 XFRM SA 和 SP
func (s *Session) updateXFRMState(localAddr, remoteAddr string) error {
	xfrmMgr := s.xfrmMgr
	if xfrmMgr == nil {
		return nil
	}

	lIP := net.ParseIP(localAddr)
	rIP := net.ParseIP(remoteAddr)
	if lIP == nil || rIP == nil {
		return fmt.Errorf("无法解析 IP: local=%s remote=%s", localAddr, remoteAddr)
	}

	var lPort, rPort int
	if sm, ok := s.socket.(*ipsec.SocketManager); ok {
		lPort = int(sm.LocalPort())
		rPort = sm.RemotePort()
		if sm.LocalIP() != nil {
			lIP = sm.LocalIP()
		}
		if sm.RemoteIP() != nil {
			rIP = sm.RemoteIP()
		}
	}

	isAEAD := driver.IsAEADAlgorithm(s.childEncrID)

	// ── 更新 SA (出站) ──
	if s.ChildSAOut != nil {
		saCfg := driver.XFRMSAConfig{
			Src: lIP, Dst: rIP,
			SPI: s.ChildSAOut.SPI, Proto: netlink.XFRM_PROTO_ESP,
			Mode: netlink.XFRM_MODE_TUNNEL, IsAEAD: isAEAD,
			EncapType:    netlink.XFRM_ENCAP_ESPINUDP,
			EncapSrcPort: lPort, EncapDstPort: rPort,
			Ifid: s.xfrmIfID, ReplayWindow: s.cfg.ReplayWindow,
		}
		if err := s.fillSAKeys(&saCfg, s.ChildSAOut, isAEAD); err != nil {
			return fmt.Errorf("填充 SAOut 密钥失败: %v", err)
		}
		if err := xfrmMgr.UpdateSA(saCfg); err != nil {
			return fmt.Errorf("更新 SAOut 失败: %v", err)
		}
	}

	// ── 更新 SA (入站) ──
	if s.ChildSAIn != nil {
		saCfg := driver.XFRMSAConfig{
			Src: rIP, Dst: lIP,
			SPI: s.ChildSAIn.SPI, Proto: netlink.XFRM_PROTO_ESP,
			Mode: netlink.XFRM_MODE_TUNNEL, IsAEAD: isAEAD,
			EncapType:    netlink.XFRM_ENCAP_ESPINUDP,
			EncapSrcPort: rPort, EncapDstPort: lPort,
			Ifid: s.xfrmIfID, ReplayWindow: s.cfg.ReplayWindow,
		}
		if err := s.fillSAKeys(&saCfg, s.ChildSAIn, isAEAD); err != nil {
			return fmt.Errorf("填充 SAIn 密钥失败: %v", err)
		}
		if err := xfrmMgr.UpdateSA(saCfg); err != nil {
			return fmt.Errorf("更新 SAIn 失败: %v", err)
		}
	}

	// ── 更新 SP (出站/入站/转发) ──
	// SP 模板中的 TmplSrc/TmplDst 指向具体 IP，必须同步更新
	for i := range s.xfrmPolicies {
		pol := &s.xfrmPolicies[i]
		if pol.TmplSrc == nil || pol.TmplDst == nil {
			continue
		}
		// 根据方向确定 TmplSrc/TmplDst
		if pol.Dir == netlink.XFRM_DIR_OUT {
			pol.TmplSrc = lIP
			pol.TmplDst = rIP
		} else {
			// IN 和 FWD: src=远端, dst=本端
			pol.TmplSrc = rIP
			pol.TmplDst = lIP
		}
		if err := xfrmMgr.UpdateSP(*pol); err != nil {
			s.Logger.Warn("更新 SP 失败",
				logger.Int("dir", int(pol.Dir)),
				logger.Err(err))
		}
	}

	// 更新缓存的 XFRM 地址
	s.xfrmLocalIP = lIP
	s.xfrmRemoteIP = rIP
	s.xfrmLocalPort = lPort
	s.xfrmRemotePort = rPort

	return nil
}

// fillSAKeys 填充 XFRM SA 的加密/完整性密钥
func (s *Session) fillSAKeys(cfg *driver.XFRMSAConfig, sa *ipsec.SecurityAssociation, isAEAD bool) error {
	if isAEAD {
		aeadInfo, err := driver.IKEv2AlgToXFRMAead(s.childEncrID, s.childEncrKeyLenBits)
		if err != nil {
			return err
		}
		cfg.AeadAlgoName = aeadInfo.Name
		cfg.AeadKey = sa.EncryptionKey
		cfg.AeadICVLen = aeadInfo.ICVBits
	} else {
		cryptInfo, err := driver.IKEv2AlgToXFRMCrypt(s.childEncrID, s.childEncrKeyLenBits)
		if err != nil {
			return err
		}
		authInfo, err := driver.IKEv2AlgToXFRMAuth(s.childIntegID)
		if err != nil {
			return err
		}
		cfg.CryptAlgoName = cryptInfo.Name
		cfg.CryptKey = sa.EncryptionKey
		cfg.AuthAlgoName = authInfo.Name
		cfg.AuthKey = sa.IntegrityKey
		cfg.AuthTruncLen = authInfo.TruncateBits
	}
	return nil
}
