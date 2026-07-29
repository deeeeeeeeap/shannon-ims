package imscore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/imsheaders"
	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/runtimehost/simauth"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

const (
	registerTransactionTimeout = 12 * time.Second
	registerCandidateTimeout   = 15 * time.Second
	registerDialTimeout        = 90 * time.Second
	// Allow initial 401 + AUTS resync 401 + one bounded follow-up challenge.
	maxChallengeRounds = 3
)

type registerState struct {
	spiC          uint32
	spiS          uint32
	portC         int
	portS         int
	transportMode string
	fromTag       string

	// generation identifies the SA this state will install, as allocated by the
	// Service. It is the token that tells a current SA from a retired one during
	// a re-registration, so it must come from the Service-owned allocator and
	// never be minted per attempt. Zero means "no generation", which the
	// protected TCP activation gate treats as never ready.
	generation uint64

	ck []byte
	ik []byte

	sipInstance   string
	selectedOffer *imsheaders.SecurityOffer
	channel       *ipsec3gpp.ProtectedChannelLease

	expiresSeconds int
	verifyHeader   string
}

type registerResult struct {
	pcscfAddr      string
	expiresSeconds int
	verifyHeader   string
	serviceRoutes  []string
	channel        *ipsec3gpp.ProtectedChannelLease
}

type initialRegisterVariant struct {
	name                       string
	initialAuth                string
	includePANI                bool
	includeCellular            bool
	requireSecAgree            bool
	proxyRequireSecAgree       bool
	omitRequireSecAgree        bool
	omitProxyRequireSecAgree   bool
	securityClientMechanism    policy.IPSec3GPPSecurityMechanism
	hasSecurityClientMechanism bool
}

func initialRejectFallbackEnabled(cfg Config) bool {
	if cfg.CarrierBehavior.RegisterTemplate.EnableInitialRejectFallback {
		return true
	}
	return strings.TrimSpace(os.Getenv("VOHIVE_IMS_INITIAL_REJECT_FALLBACK")) == "1"
}

func initialRegisterVariants(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariant{
		initialAuth:     "",
		includePANI:     templateIncludesPANI(cfg.CarrierBehavior.RegisterTemplate),
		includeCellular: true,
	}
	if cfg.CarrierBehavior.RegisterTemplate.ProbeInitialSecurityClientOnBadRequest {
		mechanisms := initialSecurityClientProbeMechanisms(cfg.CarrierBehavior.RegisterTemplate)
		variants := make([]initialRegisterVariant, 0, len(mechanisms))
		for _, mechanism := range mechanisms {
			variant := base
			variant.name = strings.TrimSpace(mechanism.Alg) + "/" + canonicalTemplateEAlg(mechanism.EAlg)
			variant.securityClientMechanism = mechanism
			variant.hasSecurityClientMechanism = true
			variants = append(variants, variant)
		}
		if len(variants) > 0 {
			return variants
		}
	}
	if cfg.CarrierBehavior.RegisterTemplate.RetryInitialWithoutRequiredSecAgreeOnBadRequest {
		withRequiredSecAgree := base
		withRequiredSecAgree.name = "with_required_sec_agree"
		withoutRequiredSecAgree := base
		withoutRequiredSecAgree.name = "without_required_sec_agree"
		withoutRequiredSecAgree.omitRequireSecAgree = true
		withoutRequiredSecAgree.omitProxyRequireSecAgree = true
		return []initialRegisterVariant{withRequiredSecAgree, withoutRequiredSecAgree}
	}
	if !initialRejectFallbackEnabled(cfg) {
		return []initialRegisterVariant{base}
	}
	return []initialRegisterVariant{
		base,
		{initialAuth: "aka_empty_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "aka_empty", includePANI: true, includeCellular: true},
		{initialAuth: "aka_zero_response_uri_first", includePANI: true, includeCellular: true},
		{initialAuth: "none", includePANI: false, includeCellular: false},
	}
}

func shouldRetryInitialRegisterForStatus(cfg Config, statusCode int) bool {
	if cfg.CarrierBehavior.RegisterTemplate.ProbeInitialSecurityClientOnBadRequest {
		return statusCode == sip.StatusBadRequest
	}
	if cfg.CarrierBehavior.RegisterTemplate.RetryInitialWithoutRequiredSecAgreeOnBadRequest {
		return statusCode == sip.StatusBadRequest
	}
	if !initialRejectFallbackEnabled(cfg) {
		return false
	}
	if statusCode == sip.StatusForbidden {
		return true
	}
	for _, code := range cfg.CarrierBehavior.RegisterTemplate.RegisterPolicy.InitialRejectFallbackStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

func runSecureAuthenticatedRegister(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state *registerState, lastReq *sip.Request, lastRes *sip.Response) (*registerResult, error) {
	// The protected transport is decided here, before anything is dialled or
	// serialized, and separately from the transport of the unprotected phase.
	//
	// The branch is taken only when the gate is on AND the decision resolved to
	// TCP. Everything else - a fitting request, an opted-out template, an explicit
	// udp configuration - falls through to the UDP path below, which runs exactly
	// as it did before Phase C: same order, same helpers, same bytes.
	//
	// handled=true means the outcome belongs to the TCP path, success or failure.
	// It must not be retried on UDP: the plan said TCP precisely because the
	// request does not fit UDP, so a downgrade would put a fragmenting request on
	// the wire.
	if protectedTCPClientProductionEnabled {
		result, handled, err := runProtectedTCPAuthenticatedRegister(
			ctx, cfg, swuTCP, state, lastReq, lastRes)
		if err != nil {
			return nil, err
		}
		if handled {
			// A TCP decision is final. It must not fall back to UDP: the plan says
			// TCP precisely because the request does not fit UDP, so a downgrade
			// would send a request that fragments.
			return result, nil
		}
	}

	secureConn, err := dialSecureRegisterConn(ctx, cfg, swuTCP, *state)
	if err != nil {
		return nil, fmt.Errorf("secure channel dial: %w", err)
	}

	authRes, _, err := buildAuthenticatedRegister(cfg, *state, lastReq, lastRes)
	if err != nil {
		_ = secureConn.Close()
		return nil, err
	}
	if err := prepareProtectedRegisterRequest(cfg, *state, authRes); err != nil {
		_ = secureConn.Close()
		return nil, err
	}

	// The protected REGISTER is the only REGISTER sent over UDP unconditionally
	// (dialSecureRegisterConn rejects anything else). Record its serialized
	// length so an RFC 3261 §18.1.1 violation is visible instead of inferred:
	// a request past that threshold on UDP may legitimately be dropped without
	// any ICMP or SIP error. Length and a bool only, never the message.
	logProtectedRegisterMessageSize(len(authRes.String()))

	secureTransport := newConnRegisterTransport(secureConn, cfg.TraceID, cfg.DeviceID, "udp")
	var sendErr error
	if usesVodafoneRegisterWireFormat(cfg) {
		payload, err := buildVodafoneProtectedRegisterPayload(authRes)
		if err != nil {
			_ = secureTransport.Close()
			return nil, err
		}
		sendErr = secureTransport.SendPayload(ctx, payload)
	} else {
		sendErr = secureTransport.Send(ctx, authRes)
	}
	if sendErr != nil {
		_ = secureTransport.Close()
		return nil, fmt.Errorf("authenticated REGISTER: %w", sendErr)
	}
	finalRes, err := secureTransport.ReadResponse(ctx)
	if err != nil {
		// No SIP response arrived on the protected channel. Emit the bounded
		// ESP counters so a silent transform/replay drop can be told apart
		// from nothing ever coming back.
		logProtectedRegisterReadFailure(state)
		_ = secureTransport.Close()
		return nil, fmt.Errorf("authenticated REGISTER: %w", err)
	}
	if !registerResponseCorrelates(authRes, finalRes) {
		_ = secureTransport.Close()
		return nil, fmt.Errorf("authenticated REGISTER response correlation mismatch")
	}
	if finalRes.StatusCode != sip.StatusOK {
		_ = secureTransport.Close()
		return nil, fmt.Errorf(
			"authenticated REGISTER failed: status=%d result=%s",
			finalRes.StatusCode,
			registerStatusResult(finalRes.StatusCode),
		)
	}
	return finalizeRegisterSuccess(cfg, *state, finalRes)
}

func usesVodafoneRegisterWireFormat(cfg Config) bool {
	return cfg.CarrierBehavior.RegisterWireFormat == policy.RegisterWireVodafoneUK
}

func registerResponseCorrelates(req *sip.Request, res *sip.Response) bool {
	if req == nil || res == nil {
		return false
	}
	reqCallID := req.GetHeader("Call-ID")
	resCallID := res.GetHeader("Call-ID")
	if reqCallID == nil || resCallID == nil || strings.TrimSpace(reqCallID.Value()) == "" || strings.TrimSpace(reqCallID.Value()) != strings.TrimSpace(resCallID.Value()) {
		return false
	}
	reqCSeq := req.GetHeader("CSeq")
	resCSeq := res.GetHeader("CSeq")
	if reqCSeq == nil || resCSeq == nil {
		return false
	}
	reqFields := strings.Fields(reqCSeq.Value())
	resFields := strings.Fields(resCSeq.Value())
	if len(reqFields) != 2 || len(resFields) != 2 {
		return false
	}
	return reqFields[0] == resFields[0] && strings.EqualFold(reqFields[1], resFields[1])
}
func installIPSecFromChallenge(cfg Config, state *registerState, res *sip.Response) error {
	secServer := res.GetHeader("Security-Server")
	if secServer == nil {
		return fmt.Errorf("missing Security-Server on %d", res.StatusCode)
	}
	verify, selected, err := buildSecurityVerifyFromChallenge(cfg, res)
	if err != nil {
		return err
	}
	state.selectedOffer = selected
	state.verifyHeader = verify

	rip := effectiveIPSecRemoteIP(cfg)
	if rip == nil {
		return fmt.Errorf("invalid IPSec remote for registrar %q transport %q", cfg.PCSCFAddr, effectiveTransportAddr(cfg))
	}

	// selected = Security-Server (P-CSCF). UE ports/SPIs remain on registerState
	// from the initial Security-Client offer.
	mech := ipsec3gpp.SecurityMechanism{
		Alg:   selected.Alg,
		EAlg:  selected.EAlg,
		Prot:  selected.Prot,
		Mode:  selected.Mode,
		SPIc:  selected.SPIC,
		SPIs:  selected.SPIS,
		PortC: selected.PortC,
		PortS: selected.PortS,
	}
	uePortC, uePortS := state.portC, state.portS
	if uePortC == 0 {
		uePortC = 5062
	}
	if uePortS == 0 {
		uePortS = 5063
	}
	policyInput := ipsec3gpp.PolicyInput{
		LocalIP:  cfg.LocalIP,
		RemoteIP: rip,
		Mech:     mech,
		CK:       state.ck,
		IK:       state.ik,
		UEPortC:  uePortC,
		UEPortS:  uePortS,
		UESPIc:   state.spiC,
		UESPIs:   state.spiS,
	}
	if state.channel == nil {
		return fmt.Errorf("protected channel lease is unavailable")
	}
	if err := state.channel.Install(policyInput); err != nil {
		return err
	}
	state.portC = state.channel.ClientPort()
	state.portS = state.channel.ServerPort()
	return nil
}

func dialSecureRegisterConn(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state registerState) (net.Conn, error) {
	if canonicalRegisterTransport(state.transportMode) != "udp" {
		return nil, fmt.Errorf("protected ESP requires UDP register transport, got %q", state.transportMode)
	}
	if swuTCP == nil {
		return nil, fmt.Errorf("protected ESP requires SWu raw IP dataplane")
	}
	rawDialer, ok := swuTCP.(voiceclient.SWURawIPDialer)
	if !ok {
		return nil, fmt.Errorf("SWu dialer does not expose raw IP")
	}
	if state.channel == nil {
		return nil, fmt.Errorf("protected channel lease is unavailable")
	}
	rip := state.channel.RemoteIP()
	if rip == nil {
		return nil, fmt.Errorf("invalid protected P-CSCF IP")
	}
	rawConn, err := rawDialer.DialContextIP(ctx, cfg.LocalIP, rip, 50)
	if err != nil {
		return nil, err
	}
	if err := state.channel.OpenUDP(rawConn); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return state.channel, nil
}

func buildAuthenticatedRegister(cfg Config, state registerState, prevReq *sip.Request, prevRes *sip.Response) (*sip.Request, *sip.Request, error) {
	if prevReq == nil {
		return nil, nil, fmt.Errorf("missing previous REGISTER request")
	}
	// Prefer the already-computed Authorization from the unprotected success
	// challenge; re-running AKA would burn another USIM vector.
	authHeader := ""
	if prevReq != nil {
		if h := prevReq.GetHeader("Authorization"); h != nil {
			authHeader = strings.TrimSpace(h.Value())
		}
	}
	if authHeader == "" {
		chal, err := selectDigestChallenge(cfg, prevRes)
		if err != nil {
			return nil, nil, err
		}
		_, header, syncFailure, err := computeAKAAuth(cfg, chal, prevReq)
		if err != nil {
			return nil, nil, err
		}
		if syncFailure {
			return nil, nil, fmt.Errorf("unexpected AUTS during protected REGISTER")
		}
		authHeader = header
	}
	req := prevReq.Clone()
	req.RemoveHeader("Via")
	req.RemoveHeader("Authorization")
	req.RemoveHeader("Security-Verify")
	req.SetTransport(strings.ToUpper(canonicalRegisterTransport(state.transportMode)))
	req.AppendHeader(sip.NewHeader("Authorization", authHeader))
	if state.verifyHeader != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", state.verifyHeader))
	}
	return req, prevReq, nil
}

// registerProtectedInnerMTU mirrors voiceclient.swuRawIPMTU, the largest inner
// IP packet the SWu raw IP connection forwards without fragmenting it.
const registerProtectedInnerMTU = 1280

// ESP transport-mode framing added by ipsec3gpp.encapsulateTransport for
// AES-CBC + HMAC-SHA-1-96: SPI(4) + sequence(4), a 16-byte IV, the ciphertext
// (block-aligned), and a 96-bit ICV. The trailer inside the ciphertext is
// pad-length(1) + next-header(1).
const (
	registerProtectedESPHeaderLen  = 8
	registerProtectedESPIVLen      = 16
	registerProtectedESPICVLen     = 12
	registerProtectedESPBlockLen   = 16
	registerProtectedESPTrailerLen = 2
	registerProtectedIPv6HeaderLen = 40
	registerProtectedUDPHeaderLen  = 8
)

// registerProtectedInnerPacketLen reports the inner IPv6 packet length produced
// by a protected REGISTER of sipLen bytes.
//
// The ESP ciphertext is block-aligned, so this is not a plain sum: a naive
// subtraction from the MTU overstates the usable SIP budget by up to a block.
func registerProtectedInnerPacketLen(sipLen int) int {
	if sipLen < 0 {
		sipLen = 0
	}
	plaintext := registerProtectedUDPHeaderLen + sipLen + registerProtectedESPTrailerLen
	blocks := (plaintext + registerProtectedESPBlockLen - 1) / registerProtectedESPBlockLen
	ciphertext := blocks * registerProtectedESPBlockLen
	return registerProtectedIPv6HeaderLen +
		registerProtectedESPHeaderLen +
		registerProtectedESPIVLen +
		ciphertext +
		registerProtectedESPICVLen
}

// protectedRegisterMaxUnfragmentedSIPLen is the largest serialized protected
// REGISTER whose inner packet still fits registerProtectedInnerMTU. Derived
// from the framing above rather than assumed: the ciphertext can only grow in
// 16-byte steps, so the last usable step is 1200 bytes and the SIP message must
// leave room for the UDP header and the ESP trailer.
const protectedRegisterMaxUnfragmentedSIPLen = registerProtectedInnerMTU -
	registerProtectedIPv6HeaderLen -
	registerProtectedESPHeaderLen -
	registerProtectedESPIVLen -
	registerProtectedESPICVLen -
	((registerProtectedInnerMTU -
		registerProtectedIPv6HeaderLen -
		registerProtectedESPHeaderLen -
		registerProtectedESPIVLen -
		registerProtectedESPICVLen) % registerProtectedESPBlockLen) -
	registerProtectedUDPHeaderLen -
	registerProtectedESPTrailerLen

// registerProtectedIPv6FragmentHeaderLen is the RFC 8200 Fragment Header that
// voiceclient.fragmentRawIPv6Packet inserts into every fragment.
const registerProtectedIPv6FragmentHeaderLen = 8

// registerProtectedRawIPPacketCount reports how many SWu raw IP packets an
// inner packet of innerLen bytes becomes.
//
// The name says "packet count", not "fragment count", on purpose: a count of 1
// is ambiguous when read as fragments (one fragment produced, or one whole
// packet?). Callers pair this with registerProtectedInnerIsFragmented so both
// facts are unambiguous.
//
// This mirrors voiceclient.fragmentRawIPv6Packet: each fragment carries the
// IPv6 header plus a Fragment Header, and every fragment payload except the last
// is a multiple of 8.
func registerProtectedRawIPPacketCount(innerLen int) int {
	if innerLen <= 0 {
		return 0
	}
	if innerLen <= registerProtectedInnerMTU {
		return 1
	}
	maxPayload := ((registerProtectedInnerMTU -
		registerProtectedIPv6HeaderLen -
		registerProtectedIPv6FragmentHeaderLen) / 8) * 8
	if maxPayload <= 0 {
		return 0
	}
	payload := innerLen - registerProtectedIPv6HeaderLen
	return (payload + maxPayload - 1) / maxPayload
}

// registerProtectedInnerIsFragmented reports whether the inner packet has to be
// fragmented to cross the SWu tunnel. This is the fact the acceptance criteria
// are stated in terms of; raw_ip_packet_count alone cannot express it without
// the reader knowing the MTU.
func registerProtectedInnerIsFragmented(innerLen int) bool {
	return innerLen > registerProtectedInnerMTU
}

// Header stripping was attempted here and reverted. The protected REGISTER is a
// clone of the INITIAL request, which 3gpp-default already builds with
// MinimalInitialHeaders, so Allow and Accept-Contact are never present to
// remove: on device the change saved 0 bytes. See
// register_production_chain_composition_test.go for the measurement that
// replaces the earlier, wrongly-based one.

func prepareProtectedRegisterRequest(cfg Config, state registerState, req *sip.Request) error {
	if req == nil {
		return fmt.Errorf("missing protected REGISTER request")
	}
	if canonicalRegisterTransport(state.transportMode) != "udp" {
		return fmt.Errorf("protected REGISTER transport must be UDP")
	}
	if state.channel == nil {
		return fmt.Errorf("protected channel lease is unavailable")
	}
	protectedServerPort := state.channel.ServerPort()
	remotePort := state.channel.RemoteClientPort()
	remoteIP := state.channel.RemoteIP()
	if protectedServerPort <= 0 || remotePort <= 0 {
		return fmt.Errorf("protected REGISTER ports are unavailable")
	}

	cseq, err := nextRegisterRequestCSeq(req)
	if err != nil {
		return err
	}
	req.RemoveHeader("Via")
	req.RemoveHeader("CSeq")
	req.PrependHeader(sip.NewHeader(
		"Via",
		fmt.Sprintf("SIP/2.0/UDP %s;branch=%s;rport", formatRegisterViaHost(cfg.LocalIP, protectedServerPort), sip.GenerateBranchN(16)),
	))
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", cseq)))
	req.ReplaceHeader(sip.NewHeader("Contact", buildIMSCoreContactForTransport(cfg, state, protectedServerPort, "udp")))
	req.SetTransport("UDP")
	req.SetDestination(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	return nil
}

func nextRegisterRequestCSeq(req *sip.Request) (uint64, error) {
	header := req.GetHeader("CSeq")
	if header == nil {
		return 0, fmt.Errorf("protected REGISTER missing CSeq")
	}
	fields := strings.Fields(header.Value())
	if len(fields) != 2 || !strings.EqualFold(fields[1], "REGISTER") {
		return 0, fmt.Errorf("invalid REGISTER CSeq %q", header.Value())
	}
	value, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse REGISTER CSeq: %w", err)
	}
	return value + 1, nil
}

func buildRegisterRequest(cfg Config, state registerState, initial bool, variant initialRegisterVariant) (*sip.Request, error) {
	recipient := sip.Uri{}
	rawURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	if err := sip.ParseUri(rawURI, &recipient); err != nil {
		return nil, err
	}
	req := sip.NewRequest(sip.REGISTER, recipient)
	fromTag := strings.TrimSpace(state.fromTag)
	if fromTag == "" {
		fromTag = sip.GenerateTagN(16)
	}
	req.AppendHeader(sip.NewHeader("From", "<"+cfg.PublicURI+">;tag="+fromTag))
	req.AppendHeader(sip.NewHeader("To", "<"+cfg.PublicURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, registerSIPLocalPort(cfg))))
	if initial {
		if auth := buildInitialAuthorization(cfg, variant.initialAuth); auth != "" {
			req.AppendHeader(sip.NewHeader("Authorization", auth))
		}
	}
	if !cfg.CarrierBehavior.RegisterTemplate.OmitRoute {
		req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(cfg)+";lr>"))
	}
	expires := cfg.RegisterExpirySeconds
	if expires <= 0 {
		expires = 3600
	}
	req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(expires)))
	supported := strings.TrimSpace(cfg.CarrierBehavior.RegisterTemplate.SupportedHeader)
	if supported == "" {
		supported = "path,sec-agree,gruu"
	}
	req.AppendHeader(sip.NewHeader("Supported", supported))
	requireSecAgree := cfg.CarrierBehavior.RegisterTemplate.RequireSecAgree
	proxyRequireSecAgree := cfg.CarrierBehavior.RegisterTemplate.ProxyRequireSecAgree
	if initial {
		requireSecAgree, proxyRequireSecAgree = initialVariantSecAgreeRequirements(cfg.CarrierBehavior.RegisterTemplate, variant)
	}
	if requireSecAgree {
		req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	}
	if proxyRequireSecAgree {
		req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	}
	minimalInitialHeaders := initial && cfg.CarrierBehavior.RegisterTemplate.MinimalInitialHeaders
	if !minimalInitialHeaders {
		req.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"))
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+cfg.PublicURI+">"))
		req.AppendHeader(sip.NewHeader("P-Visited-Network-ID", "\""+cfg.HomeDomain+"\""))
	}
	includePANI := templateIncludesPANI(cfg.CarrierBehavior.RegisterTemplate)
	includeCellular := true
	if initial {
		includePANI = variant.includePANI
		includeCellular = variant.includeCellular
	}
	if includePANI {
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", templatePANIValue(cfg.CarrierBehavior.RegisterTemplate)))
	}
	if includeCellular && !minimalInitialHeaders {
		req.AppendHeader(sip.NewHeader("Cellular-Network-Info", buildCellularNetworkInfo(cfg)))
	}
	if !minimalInitialHeaders {
		req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.smsip"))
		req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""))
	}
	var secClient string
	if initial {
		secClient = buildInitialSecurityClient(cfg.CarrierBehavior.RegisterTemplate, variant, state.spiC, state.spiS, state.portC, state.portS)
	} else if state.verifyHeader != "" {
		secClient = buildFullSecurityClient(cfg.CarrierBehavior.RegisterTemplate, state.spiC, state.spiS, state.portC, state.portS)
	} else {
		secClient = buildTemplateSecurityClient(cfg.CarrierBehavior.RegisterTemplate, state.spiC, state.spiS, state.portC, state.portS)
	}
	req.AppendHeader(sip.NewHeader("Security-Client", secClient))
	req.AppendHeader(sip.NewHeader("User-Agent", cfg.UserAgent))
	req.SetBody(nil)
	req.SetDestination(effectiveTransportAddr(cfg))
	req.SetTransport("TCP")
	return req, nil
}

func initialVariantSecAgreeRequirements(template policy.IMSRegisterTemplate, variant initialRegisterVariant) (bool, bool) {
	requireSecAgree := template.RequireSecAgree
	if variant.omitRequireSecAgree {
		requireSecAgree = false
	} else {
		requireSecAgree = requireSecAgree || variant.requireSecAgree
	}
	proxyRequireSecAgree := template.ProxyRequireSecAgree
	if variant.omitProxyRequireSecAgree {
		proxyRequireSecAgree = false
	} else {
		proxyRequireSecAgree = proxyRequireSecAgree || variant.proxyRequireSecAgree
	}
	return requireSecAgree, proxyRequireSecAgree
}

func templateIncludesPANI(template policy.IMSRegisterTemplate) bool {
	return template.IncludePANI || template.IncludePANIAuthenticated
}

func templatePANIValue(template policy.IMSRegisterTemplate) string {
	value := "IEEE-802.11;i-wlan-node-id=000000000000"
	if template.IncludePANIAuthenticated {
		value += ";network-provided"
	}
	return value
}

func finalizeRegisterSuccess(cfg Config, state registerState, res *sip.Response) (*registerResult, error) {
	expires := 3600
	if h := res.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil && v > 0 {
			expires = v
		}
	}
	logRegisterDiagnostic(registerDiagnostic{
		stage:          "complete",
		status:         res.StatusCode,
		result:         "ok",
		addressFamily:  registerAddressFamily(cfg.PCSCFAddr),
		expiresSeconds: expires,
		protected:      strings.TrimSpace(state.verifyHeader) != "",
	})
	serviceRoutes := make([]string, 0)
	for _, header := range res.GetHeaders("Service-Route") {
		if header != nil && strings.TrimSpace(header.Value()) != "" {
			serviceRoutes = append(serviceRoutes, strings.TrimSpace(header.Value()))
		}
	}
	return &registerResult{
		pcscfAddr:      cfg.PCSCFAddr,
		expiresSeconds: expires,
		verifyHeader:   state.verifyHeader,
		serviceRoutes:  serviceRoutes,
		channel:        state.channel,
	}, nil
}

func doRegisterTransaction(ctx context.Context, client *sipgo.Client, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	tx, err := client.TransactionRequest(txCtx, req, opts...)
	if err != nil {
		return nil, err
	}
	defer tx.Terminate()
	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return nil, fmt.Errorf("transaction ended: %w", err)
		}
		return nil, fmt.Errorf("transaction ended without a response")
	case res := <-tx.Responses():
		return res, nil
	case <-txCtx.Done():
		return nil, txCtx.Err()
	}
}

func buildInitialAuthorization(cfg Config, mode string) string {
	authMode := strings.ToLower(strings.TrimSpace(mode))
	if authMode == "" {
		if strings.EqualFold(strings.TrimSpace(cfg.CarrierBehavior.RegisterTemplate.SecAgreeMode), "auto") {
			authMode = "aka_empty_uri_first"
		} else if !cfg.CarrierBehavior.RegisterTemplate.UsePlainDigestPlaceholder {
			authMode = "none"
		} else {
			authMode = "aka_empty_uri_first"
		}
	}
	requestURI := "sip:" + strings.TrimSpace(cfg.HomeDomain)
	username := authorizationUsername(cfg)
	realm := quoteSipParam(strings.TrimSpace(cfg.Realm))
	switch authMode {
	case "none":
		return ""
	case "aka_empty":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="",algorithm=AKAv1-MD5`,
			quoteSipParam(username),
			realm,
			quoteSipParam(requestURI),
		)
	case "aka_zero_response_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="00000000000000000000000000000000",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	default:
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(username),
			realm,
		)
	}
}

func authorizationUsername(cfg Config) string {
	if v := strings.TrimSpace(cfg.PrivateID); v != "" {
		return v
	}
	imsi := strings.TrimSpace(cfg.IMSI)
	realm := strings.TrimSpace(cfg.Realm)
	if imsi != "" && realm != "" {
		if privateID, _ := voiceclient.BuildIMSIdentity(imsi, realm, strings.TrimSpace(cfg.HomeDomain), "imsi_home_domain"); privateID != "" {
			return privateID
		}
	}
	return ""
}

func buildIMSCoreContact(cfg Config, state registerState, localPort int) string {
	return buildIMSCoreContactForTransport(cfg, state, localPort, "tcp")
}

func buildIMSCoreContactForTransport(cfg Config, state registerState, localPort int, transport string) string {
	sipInstance := strings.TrimSpace(state.sipInstance)
	if sipInstance == "" {
		sipInstance = strings.TrimSpace(cfg.SIPInstanceURN)
	}
	if sipInstance == "" {
		sipInstance = voiceclient.NewSIPInstanceURN()
	}
	return policy.BuildIMSContactHeader(cfg.CarrierBehavior.RegisterTemplate, policy.ContactBuildInput{
		IMSI:               cfg.IMSI,
		PublicURI:          cfg.PublicURI,
		LocalIP:            cfg.LocalIP,
		LocalPort:          localPort,
		Transport:          transport,
		SIPInstanceURN:     sipInstance,
		RegisterExpirySecs: cfg.RegisterExpirySeconds,
	})
}

func buildCellularNetworkInfo(cfg Config) string {
	plmn := strings.TrimSpace(cfg.MCC) + strings.TrimLeft(strings.TrimSpace(cfg.MNC), "0")
	if plmn == "" {
		plmn = "00000"
	}
	cell := strings.TrimSpace(cfg.CellID)
	if cell == "" {
		cell = "0000000"
	}
	return fmt.Sprintf("3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s%s;cell-info-age=0", plmn, cell)
}

// computeAKAAuth runs a single USIM AKA and builds the Digest Authorization
// header. On SQN mismatch it returns an AUTS resync header with empty CK/IK
// (caller must not install IPsec until a later success challenge yields keys).
func computeAKAAuth(cfg Config, chal *digest.Challenge, req *sip.Request) (sim.AKAResult, string, bool, error) {
	if cfg.AKA == nil {
		return sim.AKAResult{}, "", false, fmt.Errorf("AKA provider required")
	}
	rawNonce, err := decodeChallengeNonce(chal.Nonce)
	if err != nil {
		return sim.AKAResult{}, "", false, err
	}
	if len(rawNonce) < 32 {
		return sim.AKAResult{}, "", false, fmt.Errorf("nonce too short for RAND||AUTN")
	}
	akaResult, akaErr := cfg.AKA.CalculateAKA(rawNonce[:16], rawNonce[16:32])

	digestURI := digestAuthorizationURI(cfg, req)
	// simauth.ComputeDigest would re-run AKA; build the header from this
	// single AKA result so AUTS and success paths never double-hit the USIM.
	result, err := simauth.ComputeDigest(fixedAKAResult{akaResult, akaErr}, chal, digest.Options{
		Method:   req.Method.String(),
		URI:      digestURI,
		Username: cfg.PrivateID,
	})
	if err != nil {
		return sim.AKAResult{}, "", false, err
	}
	return akaResult, result.Header, result.SyncFailure, nil
}

type fixedAKAResult struct {
	result sim.AKAResult
	err    error
}

func (f fixedAKAResult) CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error) {
	return f.result, f.err
}

func digestAuthorizationURI(cfg Config, req *sip.Request) string {
	if req != nil {
		if u := strings.TrimSpace(req.Recipient.String()); u != "" {
			lower := strings.ToLower(u)
			if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
				return u
			}
		}
	}
	home := strings.TrimSpace(cfg.HomeDomain)
	if home == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(home), "sip:") {
		return home
	}
	return "sip:" + home
}

func decodeChallengeNonce(nonce string) ([]byte, error) {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return nil, fmt.Errorf("empty nonce")
	}
	// Prefer hex when the token is pure even-length hex (lab logs / some stacks).
	if len(trimmed)%2 == 0 && isASCIIHexNonce(trimmed) {
		if raw, err := hex.DecodeString(trimmed); err == nil {
			return raw, nil
		}
	}
	// RFC 3310: nonce is typically base64(RAND||AUTN[||server-data]).
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return raw, nil
	}
	padded := trimmed
	for len(padded)%4 != 0 {
		padded += "="
	}
	if raw, err := base64.StdEncoding.DecodeString(padded); err == nil {
		return raw, nil
	}
	return nil, fmt.Errorf("unsupported nonce encoding")
}

func isASCIIHexNonce(value string) bool {
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func selectDigestChallenge(cfg Config, res *sip.Response) (*digest.Challenge, error) {
	headers := res.GetHeaders("WWW-Authenticate")
	if len(headers) == 0 && res.StatusCode == sip.StatusProxyAuthRequired {
		headers = res.GetHeaders("Proxy-Authenticate")
	}
	if len(headers) == 0 {
		return nil, fmt.Errorf("%d response with no authenticate header", res.StatusCode)
	}
	for _, header := range headers {
		chal, err := digest.ParseChallenge(header.Value())
		if err == nil {
			return chal, nil
		}
	}
	return nil, fmt.Errorf("parse challenge failed")
}

func quoteSipParam(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}

func registerSIPLocalPort(cfg Config) int {
	return registerAttemptLocalPort(cfg, 0)
}

func registerAttemptLocalPort(cfg Config, attemptIndex int) int {
	if attemptIndex > 0 || !registrarHostEqualsLocalIP(cfg.PCSCFAddr, cfg.LocalIP) {
		return randomEphemeralSIPPort()
	}
	return 5060
}

func randomEphemeralSIPPort() int {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(50000))
		if err != nil {
			return 5062
		}
		port := 10000 + int(n.Int64())
		if port != 5060 && port != 5061 {
			return port
		}
	}
}
