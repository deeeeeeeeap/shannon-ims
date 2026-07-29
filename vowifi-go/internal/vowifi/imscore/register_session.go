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

	"github.com/emiago/sipgo/sip"
	"github.com/google/uuid"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
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

// newRegisterSession builds an isolated session for synthetic callers. Production
// registration reserves its lease from Service.protectedChannels instead.
func newRegisterSession(cfg Config, swu voiceclient.SWUTCPDialer, network IMSNetwork, transportMode string, attemptIndex int) *registerSession {
	owner := ipsec3gpp.NewProtectedChannelOwner()
	channel, err := owner.Reserve()
	if err != nil {
		return nil
	}
	return newRegisterSessionWithChannel(cfg, swu, network, transportMode, attemptIndex, channel)
}

func newRegisterSessionWithChannel(
	cfg Config,
	swu voiceclient.SWUTCPDialer,
	network IMSNetwork,
	transportMode string,
	attemptIndex int,
	channel *ipsec3gpp.ProtectedChannelLease,
) *registerSession {
	state := &registerState{
		spiC:          channel.ClientSPI(),
		spiS:          channel.ServerSPI(),
		portC:         channel.ClientPort(),
		portS:         channel.ServerPort(),
		generation:    channel.Generation(),
		channel:       channel,
		transportMode: canonicalRegisterTransport(transportMode),
		fromTag:       sip.GenerateTagN(16),
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
	logRegisterDiagnostic(registerDiagnostic{
		stage:         "transport_connected",
		result:        "none",
		transport:     s.transportMode,
		addressFamily: registerAddressFamily(effectiveTransportAddr(s.cfg)),
	})
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
	requireSecAgree, proxyRequireSecAgree := initialVariantSecAgreeRequirements(s.cfg.CarrierBehavior.RegisterTemplate, variant)
	if strings.TrimSpace(reason) == "" {
		reason = "none"
	}
	logRegisterDiagnostic(registerDiagnostic{
		stage:            event,
		result:           reason,
		variant:          registerVariantDiagnosticName(variant),
		variantIndex:     variantIndex,
		variantTotal:     variantTotal,
		transport:        s.transportMode,
		addressFamily:    registerAddressFamily(effectiveTransportAddr(s.cfg)),
		mechanismCount:   mechanismCount,
		requiresSecAgree: requireSecAgree || proxyRequireSecAgree,
	})
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
		s.logFSM("initial_attempt", "none", i+1, len(variants), securityClientMechanismCount(s.cfg.CarrierBehavior.RegisterTemplate), variant)

		res, req, err := s.registerOnce(ctx, transport, true, variant)
		if err != nil {
			return nil, err
		}

		requireSecAgree, proxyRequireSecAgree := initialVariantSecAgreeRequirements(s.cfg.CarrierBehavior.RegisterTemplate, variant)
		// initial_response is the only stage that classifies a real Warning
		// header. The metadata is de-identified and never influences the
		// status-code state machine below.
		warning := classifyRegisterWarning(res)
		logRegisterDiagnostic(registerDiagnostic{
			stage:                "initial_response",
			status:               res.StatusCode,
			result:               registerStatusResult(res.StatusCode),
			variant:              registerVariantDiagnosticName(variant),
			variantIndex:         i + 1,
			variantTotal:         len(variants),
			transport:            s.transportMode,
			addressFamily:        registerAddressFamily(effectiveTransportAddr(s.cfg)),
			headerCount:          len(res.Headers()),
			hasWarning:           res.GetHeader("Warning") != nil,
			hasUnsupported:       res.GetHeader("Unsupported") != nil,
			hasRequire:           res.GetHeader("Require") != nil,
			requiresSecAgree:     requireSecAgree || proxyRequireSecAgree,
			hasWWWAuthenticate:   res.GetHeader("WWW-Authenticate") != nil,
			hasProxyAuthenticate: res.GetHeader("Proxy-Authenticate") != nil,
			hasSecurityServer:    res.GetHeader("Security-Server") != nil,
			hasPath:              res.GetHeader("Path") != nil,
			hasServiceRoute:      res.GetHeader("Service-Route") != nil,
			reachedAuth:          registerAttemptReachedAuthPhase(res.StatusCode),
			warningPresent:       warning.present,
			warningCount:         warning.count,
			warningCode:          warning.code,
			warningClass:         warning.class,
			warningParseResult:   warning.parseResult,
		})

		switch res.StatusCode {
		case sip.StatusOK:
			decision, err := decideInitialRegisterSuccessSecurity(s.cfg, res)
			if err != nil {
				return nil, err
			}
			s.logFSM("complete", "ok", i+1, len(variants), securityClientMechanismCount(s.cfg.CarrierBehavior.RegisterTemplate), variant)
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
			decision := decideInitialRegisterSecAgreeChallenge(s.cfg, variant, i, res)
			if decision.retry {
				secAgreeRequiredByChallenge = true
				s.logFSM("sec_agree_retry", decision.reason, i+1, len(variants), securityClientMechanismCount(s.cfg.CarrierBehavior.RegisterTemplate), variant)
				continue
			}
			lastErr = &registrarAttemptError{
				pcscf:      s.cfg.PCSCFAddr,
				statusCode: res.StatusCode,
				reason:     decision.reason,
			}
			return nil, lastErr
		default:
			outcome := decideRegisterFailureOutcome(s.cfg, res.StatusCode, res.Reason, i, len(variants), false)
			lastErr = &registrarAttemptError{
				pcscf:      s.cfg.PCSCFAddr,
				statusCode: res.StatusCode,
				reason:     outcome.reason,
			}
			if outcome.retryVariant {
				logRegisterDiagnostic(registerDiagnostic{
					stage:         "variant_retry",
					status:        res.StatusCode,
					result:        outcome.reason,
					variant:       registerVariantDiagnosticName(variant),
					variantIndex:  i + 1,
					variantTotal:  len(variants),
					transport:     s.transportMode,
					addressFamily: registerAddressFamily(effectiveTransportAddr(s.cfg)),
				})
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

type initialRegisterSecAgreeChallengeDecision struct {
	retry  bool
	reason string
}

func decideInitialRegisterSecAgreeChallenge(cfg Config, variant initialRegisterVariant, variantIndex int, res *sip.Response) initialRegisterSecAgreeChallengeDecision {
	if res == nil || res.StatusCode != sip.StatusExtensionRequired {
		return initialRegisterSecAgreeChallengeDecision{reason: "sec_agree_challenge_invalid"}
	}
	if !responseRequiresOnlySecAgree(res) {
		return initialRegisterSecAgreeChallengeDecision{reason: "sec_agree_challenge_invalid"}
	}
	requireSecAgree, proxyRequireSecAgree := initialVariantSecAgreeRequirements(cfg.CarrierBehavior.RegisterTemplate, variant)
	if requireSecAgree || proxyRequireSecAgree {
		return initialRegisterSecAgreeChallengeDecision{reason: "sec_agree_already_requested"}
	}
	if cfg.CarrierBehavior.RegisterTemplate.RetryInitialWithoutRequiredSecAgreeOnBadRequest && variantIndex > 0 {
		return initialRegisterSecAgreeChallengeDecision{reason: "sec_agree_equivalent_variant_already_rejected"}
	}
	if cfg.CarrierBehavior.RegisterTemplate.ProbeInitialSecurityClientOnBadRequest {
		return initialRegisterSecAgreeChallengeDecision{retry: true, reason: "sec_agree_required"}
	}
	return initialRegisterSecAgreeChallengeDecision{reason: "sec_agree_challenge_unsupported"}
}

func responseRequiresOnlySecAgree(res *sip.Response) bool {
	if res == nil {
		return false
	}
	count := 0
	for _, header := range res.GetHeaders("Require") {
		for _, token := range strings.Split(header.Value(), ",") {
			token = strings.TrimSpace(token)
			if token == "" || !strings.EqualFold(token, "sec-agree") {
				return false
			}
			count++
		}
	}
	return count == 1
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
			return nil, fmt.Errorf("challenge round %d: repeated AKA challenge nonce", round+1)
		}
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "auth_challenge",
			status:         lastRes.StatusCode,
			result:         "challenge_received",
			transport:      s.transportMode,
			addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
			challengeRound: round + 1,
			reachedAuth:    true,
		})
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
			logRegisterDiagnostic(registerDiagnostic{
				stage:          "auth_resync",
				status:         lastRes.StatusCode,
				result:         "resync_sent",
				transport:      s.transportMode,
				addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
				challengeRound: round + 1,
				reachedAuth:    true,
				syncFailure:    true,
			})
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
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "auth_success",
			status:         lastRes.StatusCode,
			result:         "aka_complete",
			transport:      s.transportMode,
			addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
			challengeRound: round + 1,
			reachedAuth:    true,
		})
		s.state.ck, s.state.ik = akaResult.CK, akaResult.IK
		decision, err := decideSecAgreeAfterChallenge(s.cfg, lastRes)
		if err != nil {
			return nil, newProtectedPhaseError(protectedPhaseStageIPSecInstall, err)
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
			return nil, newProtectedPhaseError(
				protectedPhaseStageIPSecInstall,
				fmt.Errorf("ipsec install: %w", err),
			)
		}
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "ipsec_install",
			result:         "installed",
			transport:      s.transportMode,
			addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
			challengeRound: round + 1,
			reachedAuth:    true,
			ipsecInstalled: true,
		})
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "protected_send",
			result:         "sending",
			transport:      s.transportMode,
			addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
			challengeRound: round + 1,
			reachedAuth:    true,
			protected:      true,
			// The SA was installed immediately above; without this the log
			// contradicted stage=ipsec_install on the previous line.
			ipsecInstalled: true,
		})
		result, err := runSecureAuthenticatedRegister(ctx, s.cfg, s.swu, s.state, newReq, lastRes)
		if err != nil {
			return nil, err
		}
		logRegisterDiagnostic(registerDiagnostic{
			stage:          "protected_accept",
			status:         sip.StatusOK,
			result:         "accepted",
			transport:      s.transportMode,
			addressFamily:  registerAddressFamily(effectiveTransportAddr(s.cfg)),
			challengeRound: round + 1,
			reachedAuth:    true,
			protected:      true,
		})
		return result, nil
	}

	if lastRes.StatusCode == sip.StatusOK {
		return finalizeRegisterSuccess(s.cfg, *s.state, lastRes)
	}
	return nil, fmt.Errorf(
		"unexpected challenged REGISTER response: status=%d result=%s",
		lastRes.StatusCode,
		registerStatusResult(lastRes.StatusCode),
	)
}

func akaChallengeNonceFingerprint(nonce string) string {
	return diagnosticFingerprint(nonce)
}

func diagnosticFingerprint(value string) string {
	trimmed := strings.TrimSpace(value)
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
	if initial && usesVodafoneRegisterWireFormat(s.cfg) {
		payload, err := buildVodafoneInitialRegisterPayload(req)
		if err != nil {
			return nil, nil, err
		}
		if err := transport.SendPayload(ctx, payload); err != nil {
			return nil, nil, err
		}
		res, err := s.readRegisterResponse(ctx, transport, req)
		return res, req, err
	}
	if err := transport.Send(ctx, req); err != nil {
		return nil, nil, err
	}
	res, err := s.readRegisterResponse(ctx, transport, req)
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
	return s.readRegisterResponse(ctx, transport, req)
}

func (s *registerSession) sendResyncRegisterRequest(ctx context.Context, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	if usesVodafoneRegisterWireFormat(s.cfg) {
		payload, err := buildVodafoneInitialRegisterPayload(req)
		if err != nil {
			return nil, err
		}
		if err := transport.SendPayload(ctx, payload); err != nil {
			return nil, err
		}
		return s.readRegisterResponse(ctx, transport, req)
	}
	return s.sendRegisterRequest(ctx, transport, req)
}

func (s *registerSession) readRegisterResponse(ctx context.Context, transport *connRegisterTransport, req *sip.Request) (*sip.Response, error) {
	res, err := transport.ReadResponse(ctx)
	if err != nil {
		return nil, err
	}
	if !registerResponseCorrelates(req, res) {
		return nil, &registrarAttemptError{
			pcscf:      s.cfg.PCSCFAddr,
			statusCode: res.StatusCode,
			reason:     "response_correlation_mismatch",
		}
	}
	return res, nil
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
	if s.phase == registerPhaseInitial && usesVodafoneRegisterWireFormat(s.cfg) {
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
