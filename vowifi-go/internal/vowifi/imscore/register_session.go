package imscore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

func resolveStableSIPInstance(cfg Config) string {
	if urn := strings.TrimSpace(cfg.SIPInstanceURN); urn != "" {
		return urn
	}
	return voiceclient.NewSIPInstanceURN()
}

type registerPhase string

const (
	registerPhaseInitial registerPhase = "initial"
	registerPhaseAuth    registerPhase = "auth"
	registerPhaseSecure  registerPhase = "secure"
)

type registerSession struct {
	cfg           Config
	swu           voiceclient.SWUTCPDialer
	network       IMSNetwork
	transportMode string
	state         *registerState
	phase         registerPhase
	jitter        bool

	conn      *connRegisterTransport
	callID    string
	cseq      uint32
	localPort int
}

func newRegisterSession(cfg Config, swu voiceclient.SWUTCPDialer, network IMSNetwork, transportMode string, attemptIndex int) *registerSession {
	spiC, spiS := randomConsecutiveSPIPair()
	state := &registerState{
		spiC:          spiC,
		spiS:          spiS,
		portC:         5062,
		portS:         5063,
		transportMode: canonicalRegisterTransport(transportMode),
		sipInstance:   resolveStableSIPInstance(cfg),
	}
	localPort := registerAttemptLocalPort(cfg, attemptIndex)
	return &registerSession{
		cfg:           cfg,
		swu:           swu,
		network:       network,
		transportMode: strings.TrimSpace(transportMode),
		state:         state,
		phase:         registerPhaseInitial,
		jitter:        true,
		callID:        uuid.NewString(),
		cseq:          nextRegisterTransportAttemptCSeq(0),
		localPort:     localPort,
	}
}

func (s *registerSession) imsNetwork() IMSNetwork {
	if s == nil {
		return nil
	}
	return s.network
}

func (s *registerSession) dialRegisterConn(ctx context.Context) (*connRegisterTransport, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: register session is nil")
	}
	if s.conn != nil {
		return s.conn, nil
	}

	if s.localPort <= 0 {
		s.localPort = registerSIPLocalPort(s.cfg)
	}
	transportAddr := effectiveTransportAddr(s.cfg)
	host, portStr, err := net.SplitHostPort(transportAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return nil, fmt.Errorf("invalid transport P-CSCF %q", transportAddr)
	}
	transport := canonicalRegisterTransport(s.transportMode)
	var raddr net.Addr
	if transport == "udp" {
		raddr = &net.UDPAddr{IP: rip, Port: port}
	} else {
		raddr = &net.TCPAddr{IP: rip, Port: port}
	}

	var rawConn net.Conn
	dialCtx := withLocalPort(ctx, s.localPort)
	switch {
	case s.network != nil:
		rawConn, err = s.network.DialContext(dialCtx, transport, raddr, transport, DialOptions{})
	case s.swu != nil:
		if transport == "udp" {
			rawConn, err = s.swu.DialContextUDP(dialCtx, s.cfg.LocalIP, s.localPort, rip, port)
		} else {
			rawConn, err = s.swu.DialContextTCP(dialCtx, s.cfg.LocalIP, s.localPort, rip, port)
		}
	default:
		if transport == "udp" {
			d := net.Dialer{LocalAddr: &net.UDPAddr{IP: s.cfg.LocalIP, Port: s.localPort}}
			rawConn, err = d.DialContext(ctx, "udp", transportAddr)
		} else {
			d := net.Dialer{LocalAddr: &net.TCPAddr{IP: s.cfg.LocalIP, Port: s.localPort}}
			rawConn, err = d.DialContext(ctx, "tcp", transportAddr)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("register dial %s: %w", transportAddr, err)
	}

	installSIPTrace(s.cfg.TraceID, s.cfg.DeviceID)
	s.conn = newConnRegisterTransport(rawConn, s.cfg.TraceID, s.cfg.DeviceID, transport)
	logger.Info("IMS REGISTER transport connected",
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("transport_mode", s.transportMode),
		logger.String("local", connLocalAddrString(s.conn.conn)),
		logger.String("remote", connRemoteAddrString(s.conn.conn)),
		logger.Int("local_port_hint", s.localPort))
	return s.conn, nil
}

func (s *registerSession) closeConn() {
	if s == nil || s.conn == nil {
		return
	}
	_ = s.conn.Close()
	s.conn = nil
}

func (s *registerSession) logFSM(event, reason string, variantIndex, variantTotal, mechanismCount int, variant initialRegisterVariant) {
	alg := ""
	ealg := ""
	if variant.hasSecurityClientMechanism {
		alg = strings.TrimSpace(variant.securityClientMechanism.Alg)
		ealg = canonicalTemplateEAlg(variant.securityClientMechanism.EAlg)
	}
	logger.Info(fmt.Sprintf("FSM(reg): %s", event),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("phase", string(s.phase)),
		logger.String("registrar", strings.TrimSpace(s.cfg.PCSCFAddr)),
		logger.String("reason", reason),
		logger.Int("variant_index", variantIndex),
		logger.Int("variant_total", variantTotal),
		logger.String("variant_name", strings.TrimSpace(variant.name)),
		logger.String("initial_auth", variant.initialAuth),
		logger.Bool("require_sec_agree", variant.requireSecAgree || s.cfg.Template.RequireSecAgree),
		logger.Bool("proxy_require_sec_agree", variant.proxyRequireSecAgree || s.cfg.Template.ProxyRequireSecAgree),
		logger.String("alg", alg),
		logger.String("ealg", ealg),
		logger.Int("security_client_mechanisms", mechanismCount),
	)
}

func (s *registerSession) runInitialRegisterFlow(ctx context.Context) (*registerResult, error) {
	if s.jitter {
		if err := waitInitialRegisterJitter(ctx, s.cfg); err != nil {
			return nil, err
		}
		s.jitter = false
	}

	transport, err := s.dialRegisterConn(ctx)
	if err != nil {
		return nil, err
	}
	defer s.closeConn()

	variants := initialRegisterVariants(s.cfg)
	var lastErr error
	secAgreeRequiredByChallenge := false
	for i := 0; i < len(variants); {
		variant := variants[i]
		if secAgreeRequiredByChallenge {
			variant.requireSecAgree = true
			variant.proxyRequireSecAgree = true
		}
		s.logFSM("initial_register_attempt", "", i+1, len(variants), securityClientMechanismCount(s.cfg.Template), variant)

		res, req, err := s.registerOnce(ctx, transport, true, variant)
		if err != nil {
			lastErr = err
			i++
			continue
		}

		logger.Info("IMS REGISTER initial response",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("pcscf", s.cfg.PCSCFAddr),
			logger.String("variant_name", strings.TrimSpace(variant.name)),
			logger.String("initial_auth", variant.initialAuth),
			logger.Bool("require_sec_agree", variant.requireSecAgree || s.cfg.Template.RequireSecAgree),
			logger.Bool("proxy_require_sec_agree", variant.proxyRequireSecAgree || s.cfg.Template.ProxyRequireSecAgree),
			logger.Bool("include_pani", variant.includePANI),
			logger.Bool("include_cellular", variant.includeCellular),
			logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason))
		logger.Info("IMS REGISTER response profile",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("status", res.StatusCode),
			logger.Int("header_count", len(res.Headers())),
			logger.Bool("has_www_authenticate", res.GetHeader("WWW-Authenticate") != nil),
			logger.Bool("has_proxy_authenticate", res.GetHeader("Proxy-Authenticate") != nil),
			logger.Bool("has_security_server", res.GetHeader("Security-Server") != nil),
			logger.Bool("has_path", res.GetHeader("Path") != nil),
			logger.Bool("has_service_route", res.GetHeader("Service-Route") != nil))

		switch res.StatusCode {
		case sip.StatusOK:
			decision, err := decideInitialRegisterSuccessSecurity(s.cfg, res)
			if err != nil {
				return nil, err
			}
			s.logFSM("initial_register_success", decision.reason, i+1, len(variants), securityClientMechanismCount(s.cfg.Template), variant)
			if decision.requireIPSec {
				if err := installIPSecFromChallenge(s.cfg, s.state, res); err != nil {
					return nil, err
				}
				s.phase = registerPhaseSecure
				return runSecureAuthenticatedRegister(ctx, s.cfg, s.swu, s.state, nil, res)
			}
			return finalizeRegisterSuccess(s.cfg, *s.state, res)
		case sip.StatusUnauthorized, sip.StatusProxyAuthRequired:
			s.phase = registerPhaseAuth
			return s.runAuthRegisterPhase(ctx, transport, req, res)
		case sip.StatusExtensionRequired:
			if shouldRetryInitialRegisterAfterSecAgreeChallenge(s.cfg, variant, res) {
				secAgreeRequiredByChallenge = true
				s.logFSM("initial_register_sec_agree_retry", "421_sec_agree_required", i+1, len(variants), securityClientMechanismCount(s.cfg.Template), variant)
				continue
			}
			lastErr = &registrarAttemptError{
				pcscf:      s.cfg.PCSCFAddr,
				statusCode: res.StatusCode,
				reason:     res.Reason,
			}
			return nil, lastErr
		default:
			lastErr = &registrarAttemptError{
				pcscf:      s.cfg.PCSCFAddr,
				statusCode: res.StatusCode,
				reason:     res.Reason,
			}
			outcome := decideRegisterFailureOutcome(s.cfg, res.StatusCode, res.Reason, i, len(variants), false)
			if outcome.retryVariant {
				logger.Info("IMS REGISTER initial reject fallback",
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.Int("status", res.StatusCode),
					logger.String("reason", res.Reason),
					logger.Int("variant_index", i+1),
					logger.Int("variant_total", len(variants)),
					logger.String("variant_name", strings.TrimSpace(variant.name)),
					logger.String("next_variant_name", strings.TrimSpace(variants[i+1].name)),
					logger.String("next_initial_auth", variants[i+1].initialAuth),
					logger.Bool("next_include_pani", variants[i+1].includePANI),
					logger.Bool("next_include_cellular", variants[i+1].includeCellular))
				i++
				continue
			}
			return nil, lastErr
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("imscore: initial REGISTER variants exhausted")
}

func shouldRetryInitialRegisterAfterSecAgreeChallenge(cfg Config, variant initialRegisterVariant, res *sip.Response) bool {
	if !cfg.Template.ProbeInitialSecurityClientOnBadRequest || res == nil || res.StatusCode != sip.StatusExtensionRequired {
		return false
	}
	requireSecAgree := cfg.Template.RequireSecAgree || variant.requireSecAgree
	proxyRequireSecAgree := cfg.Template.ProxyRequireSecAgree || variant.proxyRequireSecAgree
	if requireSecAgree || proxyRequireSecAgree {
		return false
	}
	for _, header := range res.GetHeaders("Require") {
		for _, token := range strings.Split(header.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(token), "sec-agree") {
				return true
			}
		}
	}
	return false
}

func registerResponseHeaderNames(res *sip.Response) []string {
	if res == nil {
		return nil
	}
	headers := res.Headers()
	names := make([]string, 0, len(headers))
	for _, header := range headers {
		if header != nil {
			names = append(names, header.Name())
		}
	}
	return names
}

func (s *registerSession) runAuthRegisterPhase(ctx context.Context, transport *connRegisterTransport, challengeReq *sip.Request, challengeRes *sip.Response) (*registerResult, error) {
	var lastReq = challengeReq
	var lastRes = challengeRes
	var previousNonceFingerprint string
	var previousSyncFailureAUTS []byte
	requireFreshChallenge := false

	for round := 0; round < maxChallengeRounds && (lastRes.StatusCode == 401 || lastRes.StatusCode == 407); round++ {
		// Build AKA/AUTS Authorization against this challenge first.
		if lastReq == nil {
			req, err := buildRegisterRequest(s.cfg, *s.state, false, initialRegisterVariant{})
			if err != nil {
				return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
			}
			lastReq = req
		}
		chal, err := selectDigestChallenge(s.cfg, lastRes)
		if err != nil {
			return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
		}
		nonceFingerprint := akaChallengeNonceFingerprint(chal.Nonce)
		if requireFreshChallenge && nonceFingerprint == previousNonceFingerprint {
			return nil, fmt.Errorf(
				"challenge round %d: repeated AKA challenge nonce (fingerprint=%s)",
				round+1,
				nonceFingerprint,
			)
		}
		logger.Info("IMS REGISTER AKA challenge",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("challenge_round", round+1),
			logger.String("nonce_fingerprint", nonceFingerprint))
		previousNonceFingerprint = nonceFingerprint

		akaResult, authHeader, syncFailure, err := computeAKAAuth(s.cfg, chal, lastReq)
		if err != nil {
			return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
		}

		newReq := lastReq.Clone()
		newReq.RemoveHeader("Via")
		newReq.RemoveHeader("Authorization")
		newReq.AppendHeader(sip.NewHeader("Authorization", authHeader))
		if err := s.decorateRegisterRequest(newReq); err != nil {
			return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
		}

		if syncFailure {
			if len(akaResult.AUTS) == 0 {
				return nil, fmt.Errorf("challenge round %d: sync failure without AUTS", round+1)
			}
			if len(previousSyncFailureAUTS) > 0 && bytes.Equal(previousSyncFailureAUTS, akaResult.AUTS) {
				return nil, fmt.Errorf("challenge round %d: repeated AUTS resync state", round+1)
			}
			previousSyncFailureAUTS = append(previousSyncFailureAUTS[:0], akaResult.AUTS...)
			requireFreshChallenge = true
			// RFC 3310: AUTS resync stays unprotected; network should re-401.
			logger.Info("IMS REGISTER AKA resync (AUTS) sent, awaiting fresh challenge",
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.Int("challenge_round", round+1),
				logger.Bool("sync_failure", true),
				logger.Bool("auts_present", true),
				logger.Int("auts_len", len(akaResult.AUTS)),
				logger.String("nonce_fingerprint", nonceFingerprint))
			res, err := s.sendResyncRegisterRequest(ctx, transport, newReq)
			if err != nil {
				return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
			}
			lastReq, lastRes = newReq, res
			continue
		}
		requireFreshChallenge = false

		// Success AKA: install IPsec from THIS challenge's Security-Server,
		// then send Authorization+Security-Verify on the protected channel.
		if len(akaResult.CK) == 0 || len(akaResult.IK) == 0 {
			return nil, fmt.Errorf("challenge round %d: AKA success without CK/IK", round+1)
		}
		logger.Info("IMS REGISTER AKA success",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("challenge_round", round+1),
			logger.Bool("sync_failure", false),
			logger.Int("res_len", len(akaResult.RES)),
			logger.Int("ck_len", len(akaResult.CK)),
			logger.Int("ik_len", len(akaResult.IK)),
			logger.String("nonce_fingerprint", nonceFingerprint))
		s.state.ck, s.state.ik = akaResult.CK, akaResult.IK
		decision, err := decideSecAgreeAfterChallenge(s.cfg, lastRes)
		if err != nil {
			return nil, err
		}
		if !decision.installIPSec {
			// No IPsec: fall back to unprotected authenticated REGISTER.
			if securityServer := lastRes.GetHeader("Security-Server"); securityServer != nil {
				newReq.RemoveHeader("Security-Verify")
				newReq.AppendHeader(sip.NewHeader("Security-Verify", securityServer.Value()))
			}
			res, err := s.sendRegisterRequest(ctx, transport, newReq)
			if err != nil {
				return nil, fmt.Errorf("challenge round %d: %w", round+1, err)
			}
			lastReq, lastRes = newReq, res
			if lastRes.StatusCode == sip.StatusOK {
				return finalizeRegisterSuccess(s.cfg, *s.state, lastRes)
			}
			continue
		}
		if err := installIPSecFromChallenge(s.cfg, s.state, lastRes); err != nil {
			return nil, fmt.Errorf("ipsec install: %w", err)
		}
		logger.Info("IMS IPsec installed",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("challenge_round", round+1),
			logger.Bool("ipsec_installed", true),
			logger.Bool("security_verify_present", strings.TrimSpace(s.state.verifyHeader) != ""))
		logger.Info("IMS protected authenticated REGISTER sending",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("challenge_round", round+1),
			logger.Bool("protected", true),
			logger.Bool("security_verify_present", strings.TrimSpace(s.state.verifyHeader) != ""))
		result, err := runSecureAuthenticatedRegister(ctx, s.cfg, s.swu, s.state, newReq, lastRes)
		if err != nil {
			return nil, err
		}
		logger.Info("IMS protected authenticated REGISTER accepted",
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("challenge_round", round+1),
			logger.Int("status", sip.StatusOK),
			logger.Bool("protected", true))
		return result, nil
	}

	if lastRes.StatusCode == sip.StatusOK {
		return finalizeRegisterSuccess(s.cfg, *s.state, lastRes)
	}
	return nil, fmt.Errorf("unexpected challenged REGISTER response: %d %s", lastRes.StatusCode, lastRes.Reason)
}

func akaChallengeNonceFingerprint(nonce string) string {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return "missing"
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:8])
}

func (s *registerSession) registerOnce(ctx context.Context, transport *connRegisterTransport, initial bool, variant initialRegisterVariant) (*sip.Response, *sip.Request, error) {
	req, err := buildRegisterRequest(s.cfg, *s.state, initial, variant)
	if err != nil {
		return nil, nil, err
	}
	if err := s.decorateRegisterRequest(req); err != nil {
		return nil, nil, err
	}
	if initial && strings.EqualFold(strings.TrimSpace(s.cfg.Template.ID), "vodafone_uk_23415") {
		payload, err := buildVodafoneInitialRegisterPayload(req)
		if err != nil {
			return nil, nil, err
		}
		if err := transport.SendPayload(ctx, payload); err != nil {
			return nil, nil, err
		}
		res, err := transport.ReadResponse(ctx)
		return res, req, err
	}
	if err := transport.Send(ctx, req); err != nil {
		return nil, nil, err
	}
	res, err := transport.ReadResponse(ctx)
	return res, req, err
}

func (s *registerSession) answerRegisterChallenge(ctx context.Context, transport *connRegisterTransport, prevReq *sip.Request, prevRes *sip.Response) (*sip.Response, *sip.Request, []byte, []byte, bool, error) {
	if prevReq == nil {
		req, err := buildRegisterRequest(s.cfg, *s.state, false, initialRegisterVariant{})
		if err != nil {
			return nil, nil, nil, nil, false, err
		}
		prevReq = req
	}

	chal, err := selectDigestChallenge(s.cfg, prevRes)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}

	akaResult, authHeader, syncFailure, err := computeAKAAuth(s.cfg, chal, prevReq)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}

	newReq := prevReq.Clone()
	newReq.RemoveHeader("Via")
	newReq.RemoveHeader("Authorization")
	newReq.AppendHeader(sip.NewHeader("Authorization", authHeader))
	// AUTS resync stays on the unprotected channel; do not attach Security-Verify yet.
	if !syncFailure {
		if securityServer := prevRes.GetHeader("Security-Server"); securityServer != nil {
			newReq.RemoveHeader("Security-Verify")
			newReq.AppendHeader(sip.NewHeader("Security-Verify", securityServer.Value()))
		}
	}
	if err := s.decorateRegisterRequest(newReq); err != nil {
		return nil, nil, nil, nil, false, err
	}

	res, err := s.sendRegisterRequest(ctx, transport, newReq)
	if err != nil {
		return nil, nil, nil, nil, false, err
	}
	return res, newReq, akaResult.CK, akaResult.IK, syncFailure, nil
}

func (s *registerSession) sendRegisterRequest(ctx context.Context, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	if err := transport.Send(ctx, req); err != nil {
		return nil, err
	}
	return transport.ReadResponse(ctx)
}

func (s *registerSession) sendResyncRegisterRequest(ctx context.Context, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	if strings.EqualFold(strings.TrimSpace(s.cfg.Template.ID), "vodafone_uk_23415") {
		payload, err := buildVodafoneInitialRegisterPayload(req)
		if err != nil {
			return nil, err
		}
		if err := transport.SendPayload(ctx, payload); err != nil {
			return nil, err
		}
		return transport.ReadResponse(ctx)
	}
	return s.sendRegisterRequest(ctx, transport, req)
}

func (s *registerSession) decorateRegisterRequest(req *sip.Request) error {
	if req == nil {
		return fmt.Errorf("missing REGISTER request")
	}
	req.RemoveHeader("Via")
	req.RemoveHeader("Call-ID")
	req.RemoveHeader("CSeq")
	req.RemoveHeader("Max-Forwards")

	if s.localPort <= 0 {
		s.localPort = registerSIPLocalPort(s.cfg)
	}
	transport := canonicalRegisterTransport(s.transportMode)
	req.SetTransport(strings.ToUpper(transport))
	req.ReplaceHeader(sip.NewHeader("Contact", buildIMSCoreContactForTransport(s.cfg, *s.state, s.localPort, transport)))
	viaHost := formatRegisterViaHost(s.cfg.LocalIP, s.localPort)
	via := fmt.Sprintf("SIP/2.0/%s %s;branch=%s;rport", strings.ToUpper(transport), viaHost, sip.GenerateBranchN(16))
	req.PrependHeader(sip.NewHeader("Via", via))
	req.AppendHeader(sip.NewHeader("Call-ID", s.callID))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", s.cseq)))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	if s.phase == registerPhaseInitial && strings.EqualFold(strings.TrimSpace(s.cfg.Template.ID), "vodafone_uk_23415") {
		reorderVodafoneInitialRegisterHeaders(req)
	}
	s.cseq = nextRegisterTransportAttemptCSeq(s.cseq)
	logRegisterRouting(s.cfg, req)
	return nil
}

func reorderVodafoneInitialRegisterHeaders(req *sip.Request) {
	if req == nil {
		return
	}
	headerOrder := []string{
		"Via",
		"Max-Forwards",
		"From",
		"To",
		"Call-ID",
		"CSeq",
		"Contact",
		"Expires",
		"Supported",
		"Authorization",
		"Security-Client",
		"Require",
		"Proxy-Require",
		"User-Agent",
		"Content-Length",
	}
	ordered := make([]sip.Header, 0, len(headerOrder))
	for _, name := range headerOrder {
		for _, header := range req.GetHeaders(name) {
			ordered = append(ordered, sip.HeaderClone(header))
		}
		req.RemoveHeader(name)
	}
	for _, header := range ordered {
		req.AppendHeader(header)
	}
}

func canonicalRegisterTransport(transport string) string {
	if strings.EqualFold(strings.TrimSpace(transport), "udp") {
		return "udp"
	}
	return "tcp"
}

func formatRegisterViaHost(ip net.IP, port int) string {
	if ip == nil {
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", ip.String(), port)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port)
}
