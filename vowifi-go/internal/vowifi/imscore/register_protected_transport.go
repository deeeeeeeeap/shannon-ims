package imscore

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/emiago/sipgo/sip"
)

// Protected-transport selection for the REGISTER that follows a 401.
//
// This is deliberately separate from the transport of the UNPROTECTED phase.
// registerTransportCandidates() may return ["udp","tcp"] for the resolved
// CarrierBehavior, and the
// outer loop uses that to run whole attempts. Reusing it to obtain protected TCP
// would re-send the INITIAL REGISTER over TCP, abandon the UDP session that
// already answered 401, and risk a second AKA vector, a second CSeq and a
// different candidate. So the protected transport is resolved here, once, from
// data that only exists after the SA is installed.
//
// The decision is a pure function of (CarrierBehavior, configured mode, serialized SIP
// length). No SIP status, timeout, candidate index or retry count may reach it:
// that would reintroduce "send UDP, wait, replay on TCP", which RFC 3261 does
// not define (clause 18.1.1 only specifies the TCP -> UDP fallback).

const (
	protectedTransportUDP = "udp"
	protectedTransportTCP = "tcp"
)

// Reasons are a closed enum so they can be logged without carrying any request
// data.
const (
	protectedTransportReasonFits            = "fits_udp"
	protectedTransportReasonSIPOverUDPLimit = "sip_over_udp_limit"
	protectedTransportReasonESPOverBudget   = "esp_over_budget"
	protectedTransportReasonExplicit        = "explicit"
	protectedTransportReasonTemplateOptOut  = "template_opt_out"

	// protectedTransportReasonServerFlowPending is reported when the size rule
	// selected TCP but the gate is still shut because the server flow (Phase D)
	// does not exist yet.
	//
	// A protected TCP client without a port_us listener would register and then
	// be unreachable for every network-originated request: TS 24.229 clause 3.1
	// NOTE 3 restricts downlink requests to the P-CSCF-initiated flow, so no
	// terminating INVITE, MESSAGE or reg-event NOTIFY could arrive. Registering
	// in that state is worse than staying on the current path, so the gate keeps
	// the send on UDP and records why.
	protectedTransportReasonServerFlowPending = "server_flow_pending"

	// protectedTransportReasonGenerationMismatch is reported when an activation
	// names a different SA generation than the runtime that would carry the send.
	//
	// The generation is the only thing that distinguishes a current SA from one a
	// re-registration has retired. Sending on a mismatched pair would either
	// protect the request with retired keys, or bind a port_uc that a live SA
	// already owns.
	protectedTransportReasonGenerationMismatch = "generation_mismatch"

	// protectedTransportReasonPolicyMismatch is reported when the runtime was
	// built from a different installed policy than the state being sent: a
	// different protected port pair, or a different P-CSCF.
	protectedTransportReasonPolicyMismatch = "policy_mismatch"
)

// registerSIPUDPLimit is the RFC 3261 clause 18.1.1 threshold: a request larger
// than this MUST use a congestion-controlled transport.
const registerSIPUDPLimit = 1300

// protectedRegisterPlan is the resolved decision. It holds derived integers and
// closed enums only.
type protectedRegisterPlan struct {
	// Transport is protectedTransportUDP or protectedTransportTCP. Never "auto".
	Transport string
	// Reason is why, for diagnostics.
	Reason string
	// PredictedUDPPacketLen is the inner IP packet a UDP-framed protected
	// REGISTER of this size would produce, including ESP framing.
	PredictedUDPPacketLen int
	// SIPMessageLen is the serialized length the decision was made on.
	SIPMessageLen int
}

// resolveProtectedTransport is the strict resolver for a protected send.
//
// canonicalRegisterTransport maps every non-"udp" string to "tcp", which is
// acceptable for the legacy callers it serves but must never dispatch a
// protected send: a typo or an unresolved "auto" would silently select TCP. This
// accepts only the two concrete transports and fails closed on everything else,
// including "auto", which must already have been resolved by
// decideProtectedRegisterTransport.
func resolveProtectedTransport(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case protectedTransportUDP:
		return protectedTransportUDP, nil
	case protectedTransportTCP:
		return protectedTransportTCP, nil
	default:
		return "", fmt.Errorf("imscore: protected transport %q is not a resolved transport", mode)
	}
}

// decideProtectedRegisterTransport resolves the protected transport BEFORE any
// physical write.
//
// sipMessageLen is the serialized length of the final protected request as it
// would be framed for UDP. It must be measured on a clone: see
// previewProtectedRegisterUDPLen.
func decideProtectedRegisterTransport(cfg Config, configured string, sipMessageLen int) (protectedRegisterPlan, error) {
	if sipMessageLen <= 0 {
		return protectedRegisterPlan{}, fmt.Errorf("imscore: protected REGISTER length %d is not measurable", sipMessageLen)
	}
	predicted := registerProtectedInnerPacketLen(sipMessageLen)
	plan := protectedRegisterPlan{
		PredictedUDPPacketLen: predicted,
		SIPMessageLen:         sipMessageLen,
	}

	mode := strings.ToLower(strings.TrimSpace(configured))
	switch mode {
	case protectedTransportUDP, protectedTransportTCP:
		// An explicit choice is honoured at any size, in both directions. The
		// operator asked for it; the size diagnostics still record what it costs.
		plan.Transport = mode
		plan.Reason = protectedTransportReasonExplicit
		return plan, nil
	case "", "auto":
		// fall through to the size rule
	default:
		return protectedRegisterPlan{}, fmt.Errorf("imscore: protected transport %q is not supported", configured)
	}

	switch cfg.CarrierBehavior.ProtectedAutoTransport {
	case policy.ProtectedRegisterUDPOnly:
		plan.Transport = protectedTransportUDP
		plan.Reason = protectedTransportReasonTemplateOptOut
		return plan, nil
	case "", policy.ProtectedRegisterSizeAware:
		// Continue to the size rule. The zero value preserves the generic
		// behavior for legacy synthetic Config values during migration.
	default:
		return protectedRegisterPlan{}, fmt.Errorf(
			"imscore: protected auto transport policy %q is not supported",
			cfg.CarrierBehavior.ProtectedAutoTransport,
		)
	}

	// Two independent thresholds. RFC 3261 clause 18.1.1 is about the SIP
	// message; the ESP budget is about the packet the SWu writer sees. Either one
	// alone selects TCP.
	switch {
	case sipMessageLen > registerSIPUDPLimit:
		plan.Transport = protectedTransportTCP
		plan.Reason = protectedTransportReasonSIPOverUDPLimit
	case predicted > registerProtectedInnerMTU:
		plan.Transport = protectedTransportTCP
		plan.Reason = protectedTransportReasonESPOverBudget
	default:
		plan.Transport = protectedTransportUDP
		plan.Reason = protectedTransportReasonFits
	}
	return plan, nil
}

// previewProtectedRegisterUDPLen measures what the protected request would
// serialize to, without disturbing anything.
//
// It works on a CLONE and is used for arithmetic only. Measuring on the base
// request itself would advance its CSeq and add a Via, so the request actually
// sent would carry a second increment - the state drift this whole split exists
// to avoid.
func previewProtectedRegisterUDPLen(cfg Config, state registerState, base *sip.Request) (int, error) {
	if base == nil {
		return 0, errors.New("imscore: protected REGISTER preview requires a base request")
	}
	preview := base.Clone()
	if err := applyProtectedRegisterTransport(cfg, state, preview, protectedTransportUDP); err != nil {
		return 0, err
	}
	return len(preview.String()), nil
}

// buildFinalProtectedRegisterRequest produces the one request that will be sent,
// from the untouched transport-neutral base.
//
// The base is cloned, so the caller may build for either transport and the base
// remains the single source of truth for CSeq.
func buildFinalProtectedRegisterRequest(cfg Config, state registerState, base *sip.Request, transport string) (*sip.Request, error) {
	if base == nil {
		return nil, errors.New("imscore: protected REGISTER requires a base request")
	}
	resolved, err := resolveProtectedTransport(transport)
	if err != nil {
		return nil, err
	}
	final := base.Clone()
	if err := applyProtectedRegisterTransport(cfg, state, final, resolved); err != nil {
		return nil, err
	}
	return final, nil
}

// applyProtectedRegisterTransport stamps the transport-specific headers onto a
// request that already carries Authorization, Security-Client and
// Security-Verify.
//
// Per-transport differences, and why:
//
//   - Via transport token: RFC 3261 clause 18.1.1 requires it to match the
//     transport actually used.
//   - Via sent-by port and rport: TS 24.229 clause 5.1.1.2.2 c) scopes the
//     protected-server-port requirement to UDP, and clause 5.1.1.2.1 d) states
//     that for TCP the response arrives on the connection the request was sent
//     on. rport is a UDP artefact, and the P-CSCF ignores it on a protected
//     request anyway (clause 5.2.2.2).
//   - Contact: no transport qualifier in the spec, so it keeps the protected
//     server port in both cases.
func applyProtectedRegisterTransport(cfg Config, state registerState, req *sip.Request, transport string) error {
	if req == nil {
		return errors.New("imscore: missing protected REGISTER request")
	}
	if state.channel == nil {
		return errors.New("imscore: protected channel lease is unavailable")
	}
	protectedServerPort := state.channel.ServerPort()
	remotePort := state.channel.RemoteClientPort()
	remoteIP := state.channel.RemoteIP()
	if protectedServerPort <= 0 || remotePort <= 0 {
		return errors.New("imscore: protected REGISTER ports are unavailable")
	}

	cseq, err := nextRegisterRequestCSeq(req)
	if err != nil {
		return err
	}
	req.RemoveHeader("Via")
	req.RemoveHeader("CSeq")

	switch transport {
	case protectedTransportUDP:
		req.PrependHeader(sip.NewHeader(
			"Via",
			fmt.Sprintf("SIP/2.0/UDP %s;branch=%s;rport",
				formatRegisterViaHost(cfg.LocalIP, protectedServerPort), sip.GenerateBranchN(16)),
		))
		req.SetTransport("UDP")
	case protectedTransportTCP:
		// No sent-by port and no rport: the response comes back on this
		// connection, so there is nothing for the peer to reach us on.
		req.PrependHeader(sip.NewHeader(
			"Via",
			fmt.Sprintf("SIP/2.0/TCP %s;branch=%s",
				formatRegisterViaHostNoPort(cfg.LocalIP), sip.GenerateBranchN(16)),
		))
		req.SetTransport("TCP")
	default:
		return fmt.Errorf("imscore: protected transport %q is not resolved", transport)
	}

	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", cseq)))
	req.ReplaceHeader(sip.NewHeader("Contact",
		buildIMSCoreContactForTransport(cfg, state, protectedServerPort, transport)))
	req.SetDestination(net.JoinHostPort(remoteIP.String(), strconv.Itoa(remotePort)))
	return nil
}

// formatRegisterViaHostNoPort renders a Via sent-by host with no port, for TCP.
func formatRegisterViaHostNoPort(ip net.IP) string {
	if ip == nil {
		return "127.0.0.1"
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]", ip.String())
	}
	return ip.String()
}
