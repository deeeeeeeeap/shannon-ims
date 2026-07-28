package swu

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	//"encoding/hex"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

type InvalidKEPayloadError struct {
	group uint16
}

func (e *InvalidKEPayloadError) Error() string {
	return fmt.Sprintf("IKE_SA_INIT peer requested DH group %d", e.group)
}

func (e *InvalidKEPayloadError) SuggestedDHGroup() uint16 {
	return e.group
}

func detectOutboundIPv4(remoteIP net.IP, remotePort uint16) (net.IP, error) {
	if remoteIP == nil {
		return nil, errors.New("remote ip is nil")
	}
	r := &net.UDPAddr{IP: remoteIP, Port: int(remotePort)}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, errors.New("cannot detect outbound ip")
}

func (s *Session) sendIKESAInit() error {
	data, err := s.buildIKESAInitPacket()
	if err != nil {
		return err
	}
	return s.socket.SendIKE(data)
}

func (s *Session) buildIKESAInitPacket() ([]byte, error) {
	if len(s.ni) == 0 {
		s.ni = make([]byte, 32)
		rand.Read(s.ni)
	}

	if s.DH == nil {
		var err error
		s.DH, err = crypto.NewDiffieHellman(14)
		if err != nil {
			return nil, err
		}
		if err := s.DH.GenerateKey(); err != nil {
			return nil, err
		}
	}

	proposals := ikeProposalsForDH(s.DH.Group)
	if len(proposals) == 0 {
		return nil, fmt.Errorf("no IKE proposal supports DH group %d", s.DH.Group)
	}

	saPayload := &ikev2.EncryptedPayloadSA{
		Proposals: proposals,
	}

	kePayload := &ikev2.EncryptedPayloadKE{
		DHGroup: ikev2.AlgorithmType(s.DH.Group),
		KEData:  s.DH.PublicKeyBytes(),
	}

	noncePayload := &ikev2.EncryptedPayloadNonce{
		NonceData: s.ni,
	}

	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}

	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	if localIP == nil || localIP.Equal(net.IPv4zero) {
		if remoteIP != nil {
			if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
				localIP = out
			}
		}
	}

	srcHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, localIP, localPort)
	natSrcPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_SOURCE_IP, srcHash)

	dstHash := ikev2.CalculateNATDetectionHash(s.SPIi, 0, remoteIP, remotePort)
	natDstPayload := ikev2.CreateNATDetectionNotify(ikev2.NAT_DETECTION_DESTINATION_IP, dstHash)

	// IKE Fragmentation (RFC 7383)
	// IKE_SA_INIT 必须携带此通知
	fragNotify := &ikev2.EncryptedPayloadNotify{
		ProtocolID: 0,
		NotifyType: ikev2.IKEV2_FRAGMENTATION_SUPPORTED,
	}

	// 顺序: SA, KE, Nonce, FRAG, [COOKIE], NAT_SRC, NAT_DST

	payloads := []ikev2.Payload{saPayload, kePayload, noncePayload, fragNotify}
	if s.sendCookie && len(s.cookie) > 0 {
		payloads = append(payloads, &ikev2.EncryptedPayloadNotify{
			ProtocolID: 0,
			NotifyType: ikev2.COOKIE,
			NotifyData: s.cookie,
		})
	}
	payloads = append(payloads, natSrcPayload, natDstPayload)

	packet := ikev2.NewIKEPacket()
	packet.Header.SPIi = s.SPIi
	packet.Header.Version = 0x20
	packet.Header.ExchangeType = ikev2.IKE_SA_INIT
	packet.Header.Flags = ikev2.FlagInitiator
	packet.Header.MessageID = 0
	packet.Payloads = payloads

	data, err := packet.Encode()
	if err != nil {
		return nil, err
	}

	s.msgBuffer = data
	return data, nil
}

func ikeProposalsForDH(group uint16) []*ikev2.Proposal {
	candidates := ikev2.CreateMultiProposalIKE(nil)
	proposals := make([]*ikev2.Proposal, 0, len(candidates))
	for _, proposal := range candidates {
		matches := false
		for _, transform := range proposal.Transforms {
			if transform.Type != ikev2.TransformTypeDH {
				continue
			}
			if matches || uint16(transform.ID) != group {
				matches = false
				break
			}
			matches = true
		}
		if !matches {
			continue
		}
		proposal.ProposalNum = uint8(len(proposals) + 1)
		proposals = append(proposals, proposal)
	}
	return proposals
}

func (s *Session) prepareIKESAInitRetry(group uint16) error {
	if group != uint16(ikev2.MODP_3072_bit) {
		return fmt.Errorf("IKE_SA_INIT peer requested unsupported DH group %d", group)
	}
	dh, err := crypto.NewDiffieHellman(group)
	if err != nil {
		return fmt.Errorf("IKE_SA_INIT peer requested unsupported DH group %d", group)
	}
	if err := dh.GenerateKey(); err != nil {
		return fmt.Errorf("generate IKE_SA_INIT DH material: %w", err)
	}
	s.DH = dh
	s.ni = nil
	s.nr = nil
	s.SPIr = 0
	s.Keys = nil
	s.msgBuffer = nil
	return nil
}

func (s *Session) handleIKESAInitResp(data []byte) error {
	if err := validateIKESAInitResponseEnvelope(data, s.SPIi); err != nil {
		return err
	}
	packet, err := ikev2.DecodePacket(data)
	if err != nil {
		return fmt.Errorf("解码 SA_INIT 响应失败: %v", err)
	}

	// 提取载荷
	var saPayload *ikev2.EncryptedPayloadSA
	var kePayload *ikev2.EncryptedPayloadKE
	var noncePayload *ikev2.EncryptedPayloadNonce
	var natSrc []byte
	var natDst []byte
	var invalidKE *InvalidKEPayloadError
	cookieRequired := false

	for _, p := range packet.Payloads {
		switch v := p.(type) {
		case *ikev2.EncryptedPayloadSA:
			saPayload = v
		case *ikev2.EncryptedPayloadKE:
			kePayload = v
		case *ikev2.EncryptedPayloadNonce:
			noncePayload = v
		case *ikev2.EncryptedPayloadNotify:
			if v.NotifyType == ikev2.INVALID_KE_PAYLOAD {
				if v.ProtocolID != 0 || len(v.SPI) != 0 || len(v.NotifyData) != 2 {
					return errors.New("malformed INVALID_KE_PAYLOAD notify")
				}
				group := binary.BigEndian.Uint16(v.NotifyData)
				if group == 0 || invalidKE != nil {
					return errors.New("malformed INVALID_KE_PAYLOAD notify")
				}
				invalidKE = &InvalidKEPayloadError{group: group}
				continue
			}
			if v.NotifyType == ikev2.COOKIE {
				if err := s.handleCookie(v.NotifyData); err != nil {
					return err
				}
				cookieRequired = true
				continue
			}
			if v.NotifyType == ikev2.NAT_DETECTION_SOURCE_IP {
				natSrc = v.NotifyData
			}
			if v.NotifyType == ikev2.NAT_DETECTION_DESTINATION_IP {
				natDst = v.NotifyData
			}
			// IKE Fragmentation (RFC 7383)
			if v.NotifyType == ikev2.IKEV2_FRAGMENTATION_SUPPORTED {
				s.fragmentationSupported = true
				s.Logger.Info("ePDG 支持 IKE Fragmentation")
			}
			// 检查错误，如 NO_PROPOSAL_CHOSEN
			if v.NotifyType == 14 { // NO_PROPOSAL_CHOSEN
				return errors.New("服务器拒绝了提议 (NO_PROPOSAL_CHOSEN)")
			}
			// RFC 5685: REDIRECT
			if v.NotifyType == ikev2.REDIRECT {
				addr, err := ParseRedirectData(v.NotifyData)
				if err != nil {
					s.Logger.Warn("解析 REDIRECT 数据失败", logger.Err(err))
				} else {
					return &RedirectError{NewAddr: addr}
				}
			}
		}
	}
	if invalidKE != nil {
		return invalidKE
	}
	if cookieRequired {
		return ErrCookieRequired
	}

	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return errors.New("SA_INIT 响应中缺少强制性载荷")
	}

	if len(saPayload.Proposals) != 1 {
		return errors.New("IKE_SA_INIT response must select exactly one proposal")
	}

	// 处理 SA 选择。
	selProp := saPayload.Proposals[0]
	var prfID uint16
	var encrID uint16
	var encrKeyLenBits int
	var integID uint16
	var dhID uint16

	for _, t := range selProp.Transforms {
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
		case ikev2.TransformTypePRF:
			prfID = uint16(t.ID)
		case ikev2.TransformTypeDH:
			dhID = uint16(t.ID)
		}
	}
	if s.DH == nil || dhID == 0 || uint16(kePayload.DHGroup) != dhID || dhID != s.DH.Group {
		return errors.New("IKE_SA_INIT response DH selection does not match KE")
	}

	s.Logger.Info("IKE_SA_INIT algorithms selected",
		logger.String("encr", ikev2.EncrToString(encrID)),
		logger.Int("encr_key_bits", encrKeyLenBits),
		logger.String("integ", ikev2.IntegToString(integID)),
		logger.String("prf", ikev2.PRFToString(prfID)),
		logger.String("dh", ikev2.DHToString(dhID)),
	)

	// 设置加密实例
	s.PRFAlg, err = crypto.GetPRF(prfID)
	if err != nil {
		return fmt.Errorf("选择了不支持的 PRF: %d", prfID)
	}

	s.EncAlg, err = crypto.GetEncrypterWithKeyLen(encrID, encrKeyLenBits)
	if err != nil {
		return fmt.Errorf("选择了不支持的 Encr: %d", encrID)
	}
	s.ikeEncrID = encrID
	s.ikeIsAEAD = encrID == uint16(ikev2.ENCR_AES_GCM_16) || encrID == uint16(ikev2.ENCR_AES_GCM_12) || encrID == uint16(ikev2.ENCR_AES_GCM_8)
	if s.ikeIsAEAD {
		s.ikeIntegID = 0
		s.IntegAlg, _ = crypto.GetIntegrityAlgorithm(0)
	} else {
		s.ikeIntegID = integID
		s.IntegAlg, err = crypto.GetIntegrityAlgorithm(integID)
		if err != nil {
			return fmt.Errorf("选择了不支持的 Integ: %d", integID)
		}
	}

	s.SPIr = packet.Header.SPIr
	s.nr = append([]byte(nil), noncePayload.NonceData...)
	rollbackResponderState := func() {
		s.SPIr = 0
		s.nr = nil
		s.Keys = nil
	}

	// 计算共享密钥
	if _, err := s.DH.ComputeSharedSecret(kePayload.KEData); err != nil {
		rollbackResponderState()
		return fmt.Errorf("DH 计算失败: %v", err)
	}

	// 计算密钥
	s.Logger.Debug("正在生成密钥材料")
	if err := s.GenerateIKESAKeys(s.nr); err != nil {
		rollbackResponderState()
		return err
	}
	s.applyIKESAInitNATDetection(natSrc, natDst)

	s.sendCookie = false
	return nil
}

func (s *Session) applyIKESAInitNATDetection(natSrc, natDst []byte) {
	if len(natSrc) == 0 || len(natDst) == 0 {
		return
	}
	localPort := s.cfg.LocalPort
	if localPort == 0 {
		if lp, ok := s.socket.(interface{ LocalPort() uint16 }); ok {
			localPort = lp.LocalPort()
		}
	}
	remoteIP := net.ParseIP(s.cfg.EpDGAddr).To4()
	remotePort := s.cfg.EpDGPort
	if remotePort == 0 {
		remotePort = 500
	}
	if ep, ok := s.socket.(interface {
		LocalIP() net.IP
		RemoteIP() net.IP
		RemotePort() int
	}); ok {
		if rip := ep.RemoteIP(); rip != nil {
			if v4 := rip.To4(); v4 != nil {
				remoteIP = v4
			}
		}
		if rp := ep.RemotePort(); rp != 0 {
			remotePort = uint16(rp)
		}
	}

	localIP := net.ParseIP(s.cfg.LocalAddr).To4()
	if ep, ok := s.socket.(interface{ LocalIP() net.IP }); ok {
		if lip := ep.LocalIP(); lip != nil {
			if v4 := lip.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
				localIP = v4
			}
		}
	}
	if localIP == nil || localIP.Equal(net.IPv4zero) {
		if remoteIP != nil {
			if out, err := detectOutboundIPv4(remoteIP, remotePort); err == nil && out != nil {
				localIP = out
			}
		}
	}

	expNatSrc := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, localIP, localPort)
	expNatDst := ikev2.CalculateNATDetectionHash(s.SPIi, s.SPIr, remoteIP, remotePort)

	if !bytes.Equal(natSrc, expNatSrc) || !bytes.Equal(natDst, expNatDst) {
		if setter, ok := s.socket.(interface{ SetRemotePort(int) }); ok {
			setter.SetRemotePort(4500)
		}
		s.startNATKeepalive(20 * time.Second)
		s.Logger.Debug("检测到 NAT，切换到 UDP 4500")
	}
}

func validateIKESAInitResponseEnvelope(data []byte, expectedSPIi uint64) error {
	header, err := ikev2.DecodeHeader(data)
	if err != nil {
		return fmt.Errorf("invalid IKE_SA_INIT response header: %w", err)
	}
	if header.Version != 0x20 || header.ExchangeType != ikev2.IKE_SA_INIT || header.Flags != ikev2.FlagResponse {
		return errors.New("invalid IKE_SA_INIT response header")
	}
	if header.MessageID != 0 || header.SPIi != expectedSPIi {
		return errors.New("uncorrelated IKE_SA_INIT response")
	}
	if header.Length != uint32(len(data)) {
		return errors.New("invalid IKE_SA_INIT response length")
	}

	offset := ikev2.IKE_HEADER_LEN
	nextPayload := header.NextPayload
	for nextPayload != ikev2.NoNextPayload {
		if offset+ikev2.PAYLOAD_HEADER_LEN > len(data) {
			return errors.New("truncated IKE_SA_INIT payload chain")
		}
		payloadLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		if payloadLength < ikev2.PAYLOAD_HEADER_LEN || offset+payloadLength > len(data) {
			return errors.New("invalid IKE_SA_INIT payload length")
		}
		nextPayload = ikev2.PayloadType(data[offset])
		offset += payloadLength
	}
	if offset != len(data) {
		return errors.New("invalid IKE_SA_INIT payload chain length")
	}
	return nil
}

func ParseRedirectData(data []byte) (string, error) {
	if len(data) < 1 {
		return "", errors.New("empty redirect data")
	}
	gwType := data[0]
	gwData := data[1:]

	switch gwType {
	case ikev2.RedirectGWIPv4: // IPv4
		if len(gwData) != 4 {
			return "", fmt.Errorf("invalid IPv4 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWIPv6: // IPv6
		if len(gwData) != 16 {
			return "", fmt.Errorf("invalid IPv6 length: %d", len(gwData))
		}
		return net.IP(gwData).String(), nil
	case ikev2.RedirectGWFQDN: // FQDN
		return string(gwData), nil
	default:
		return "", fmt.Errorf("unknown gateway identity type: %d", gwType)
	}
}
