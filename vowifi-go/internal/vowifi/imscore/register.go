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

	"github.com/1239t/swu-go/pkg/logger"
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

	ck []byte
	ik []byte

	sipInstance   string
	selectedOffer *imsheaders.SecurityOffer
	ipsecPolicy   ipsec3gpp.Policy
	transport     *ipsec3gpp.Transport
	secureConn    *ipsec3gpp.SecureChannelConn

	expiresSeconds int
	verifyHeader   string
}

type registerResult struct {
	pcscfAddr      string
	expiresSeconds int
	verifyHeader   string
	serviceRoutes  []string
	secureConn     *ipsec3gpp.SecureChannelConn
	ipsecPolicy    ipsec3gpp.Policy
	transport      *ipsec3gpp.Transport
}

type initialRegisterVariant struct {
	name                       string
	initialAuth                string
	includePANI                bool
	includeCellular            bool
	requireSecAgree            bool
	proxyRequireSecAgree       bool
	securityClientMechanism    policy.IPSec3GPPSecurityMechanism
	hasSecurityClientMechanism bool
}

func initialRejectFallbackEnabled(cfg Config) bool {
	if cfg.Template.EnableInitialRejectFallback {
		return true
	}
	return strings.TrimSpace(os.Getenv("VOHIVE_IMS_INITIAL_REJECT_FALLBACK")) == "1"
}

func initialRegisterVariants(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariant{
		initialAuth:     "",
		includePANI:     templateIncludesPANI(cfg.Template),
		includeCellular: true,
	}
	if cfg.Template.ProbeInitialSecurityClientOnBadRequest {
		mechanisms := initialSecurityClientProbeMechanisms(cfg.Template)
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
	if cfg.Template.ProbeInitialSecurityClientOnBadRequest {
		return statusCode == sip.StatusBadRequest
	}
	if !initialRejectFallbackEnabled(cfg) {
		return false
	}
	if statusCode == sip.StatusForbidden {
		return true
	}
	for _, code := range cfg.Template.RegisterPolicy.InitialRejectFallbackStatusCodes {
		if code == statusCode {
			return true
		}
	}
	return false
}

func runSecureAuthenticatedRegister(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state *registerState, lastReq *sip.Request, lastRes *sip.Response) (*registerResult, error) {
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

	secureTransport := newConnRegisterTransport(secureConn, cfg.TraceID, cfg.DeviceID, "udp")
	var sendErr error
	if strings.EqualFold(strings.TrimSpace(cfg.Template.ID), "vodafone_uk_23415") {
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
		_ = secureTransport.Close()
		return nil, fmt.Errorf("authenticated REGISTER: %w", err)
	}
	if finalRes.StatusCode != sip.StatusOK {
		_ = secureTransport.Close()
		return nil, fmt.Errorf("authenticated REGISTER failed: %d %s", finalRes.StatusCode, finalRes.Reason)
	}
	_ = secureTransport.ReleaseConn()

	state.secureConn = secureConn
	return finalizeRegisterSuccess(cfg, *state, finalRes)
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
	pol, err := ipsec3gpp.NewPolicy(ipsec3gpp.PolicyInput{
		LocalIP:  cfg.LocalIP,
		RemoteIP: rip,
		Mech:     mech,
		CK:       state.ck,
		IK:       state.ik,
		UEPortC:  uePortC,
		UEPortS:  uePortS,
		UESPIc:   state.spiC,
		UESPIs:   state.spiS,
	})
	if err != nil {
		return err
	}
	state.portC = pol.LocalPortC
	state.portS = pol.LocalPortS
	transport, err := ipsec3gpp.NewTransport(pol)
	if err != nil {
		return err
	}
	state.ipsecPolicy = pol
	state.transport = transport
	return nil
}

func dialSecureRegisterConn(ctx context.Context, cfg Config, swuTCP voiceclient.SWUTCPDialer, state registerState) (*ipsec3gpp.SecureChannelConn, error) {
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
	rip := net.IP(state.ipsecPolicy.RemoteIP)
	if rip == nil {
		return nil, fmt.Errorf("invalid protected P-CSCF IP")
	}
	rawConn, err := rawDialer.DialContextIP(ctx, cfg.LocalIP, rip, 50)
	if err != nil {
		return nil, err
	}
	return ipsec3gpp.WrapSecureChannelUDP(rawConn, state.transport, state.ipsecPolicy), nil
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

func prepareProtectedRegisterRequest(cfg Config, state registerState, req *sip.Request) error {
	if req == nil {
		return fmt.Errorf("missing protected REGISTER request")
	}
	if canonicalRegisterTransport(state.transportMode) != "udp" {
		return fmt.Errorf("protected REGISTER transport must be UDP")
	}
	protectedServerPort := state.ipsecPolicy.FlowS.LocalPort
	remotePort := state.ipsecPolicy.FlowC.RemotePort
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
	req.SetDestination(net.JoinHostPort(net.IP(state.ipsecPolicy.RemoteIP).String(), strconv.Itoa(remotePort)))
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
	req.AppendHeader(sip.NewHeader("From", "<"+cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<"+cfg.PublicURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", buildIMSCoreContact(cfg, state, registerSIPLocalPort(cfg))))
	if initial {
		if auth := buildInitialAuthorization(cfg, variant.initialAuth); auth != "" {
			req.AppendHeader(sip.NewHeader("Authorization", auth))
		}
	}
	if !cfg.Template.OmitRoute {
		req.AppendHeader(sip.NewHeader("Route", "<sip:"+effectiveRouteAddr(cfg)+";lr>"))
	}
	expires := cfg.RegisterExpirySeconds
	if expires <= 0 {
		expires = 3600
	}
	req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(expires)))
	supported := strings.TrimSpace(cfg.Template.SupportedHeader)
	if supported == "" {
		supported = "path,sec-agree,gruu"
	}
	req.AppendHeader(sip.NewHeader("Supported", supported))
	requireSecAgree := cfg.Template.RequireSecAgree
	proxyRequireSecAgree := cfg.Template.ProxyRequireSecAgree
	if initial {
		requireSecAgree = requireSecAgree || variant.requireSecAgree
		proxyRequireSecAgree = proxyRequireSecAgree || variant.proxyRequireSecAgree
	}
	if requireSecAgree {
		req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
	}
	if proxyRequireSecAgree {
		req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
	}
	minimalInitialHeaders := initial && cfg.Template.MinimalInitialHeaders
	if !minimalInitialHeaders {
		req.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"))
		req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+cfg.PublicURI+">"))
		req.AppendHeader(sip.NewHeader("P-Visited-Network-ID", "\""+cfg.HomeDomain+"\""))
	}
	includePANI := templateIncludesPANI(cfg.Template)
	includeCellular := true
	if initial {
		includePANI = variant.includePANI
		includeCellular = variant.includeCellular
	}
	if includePANI {
		req.AppendHeader(sip.NewHeader("P-Access-Network-Info", templatePANIValue(cfg.Template)))
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
		secClient = buildInitialSecurityClient(cfg.Template, variant, state.spiC, state.spiS, state.portC, state.portS)
	} else if state.verifyHeader != "" {
		secClient = buildFullSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	} else {
		secClient = buildTemplateSecurityClient(cfg.Template, state.spiC, state.spiS, state.portC, state.portS)
	}
	req.AppendHeader(sip.NewHeader("Security-Client", secClient))
	req.AppendHeader(sip.NewHeader("User-Agent", cfg.UserAgent))
	req.SetBody(nil)
	req.SetDestination(effectiveTransportAddr(cfg))
	req.SetTransport("TCP")
	return req, nil
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
	logger.Info(fmt.Sprintf("[%s] IMS REGISTER 成功", strings.TrimSpace(cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.Int("code", res.StatusCode),
		logger.Int("expires_seconds", expires),
		logger.String("sip_security_mode", "ipsec3gpp"),
		logger.Bool("security_verify_present", strings.TrimSpace(state.verifyHeader) != ""),
		logger.Int("security_verify_len", len(strings.TrimSpace(state.verifyHeader))))
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
		secureConn:     state.secureConn,
		ipsecPolicy:    state.ipsecPolicy,
		transport:      state.transport,
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
		if strings.EqualFold(strings.TrimSpace(cfg.Template.SecAgreeMode), "auto") {
			authMode = "aka_empty_uri_first"
		} else if !cfg.Template.UsePlainDigestPlaceholder {
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
	return policy.BuildIMSContactHeader(cfg.Template, policy.ContactBuildInput{
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

func randomNonZeroUint32() uint32 {
	// Prefer signed 31-bit SPI values (1..0x7fffffff); some IMS stacks reject high-bit SPIs.
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(0x7fffffff))
		if err != nil {
			return 0x00ffee01
		}
		if v := uint32(n.Int64()) + 1; v != 0 {
			return v
		}
	}
}

// randomConsecutiveSPIPair returns Qualcomm-style 31-bit consecutive SPIs: spi-c=base, spi-s=base+1.
func randomConsecutiveSPIPair() (spiC, spiS uint32) {
	// base in [1, 0x7ffffffe] so base+1 stays within signed 31-bit positive range.
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(0x7ffffffe))
		if err != nil {
			return 0x00ffee01, 0x00ffee02
		}
		base := uint32(n.Int64()) + 1
		if base >= 1 && base <= 0x7ffffffe {
			return base, base + 1
		}
	}
}
