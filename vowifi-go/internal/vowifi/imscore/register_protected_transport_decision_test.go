package imscore

import (
	"strings"
	"testing"

	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/emiago/sipgo/sip"
)

// Phase C1: decide the PROTECTED transport before anything is written, and keep
// that decision strictly separate from the transport of the unprotected phase.
//
// The trap this file exists to prevent: `transportMode` currently drives BOTH
// phases, and registerTransportCandidates() returns ["udp","tcp"] for
// 3gpp-default. So "just retry with TCP" at the outer layer would re-send the
// INITIAL REGISTER over TCP, abandon the UDP session that already answered 401,
// and risk a second AKA vector, a second CSeq and a different candidate.
//
// The protected transport must therefore be resolved from data that only exists
// AFTER the 401 has been answered and the SA installed:
//
//	initialTransportMode   - the attempt's unprotected transport, unchanged
//	protectedTransportMode - resolved once, from the serialized request length
//
// Assertions are lengths, counts, enums and booleans. No SIP text, identity,
// address, port value, SPI or key material is asserted or logged.

// ---------------------------------------------------------------------------
// C1.3: the resolver must be strict. The existing canonicalRegisterTransport
// maps every non-"udp" string to "tcp", which is fine for the legacy callers it
// serves but must never be used to dispatch a protected send.
// ---------------------------------------------------------------------------

func TestProtectedTransportDecisionRejectsUnknownMode(t *testing.T) {
	// Guard the premise: the legacy helper really is a silent fallback, which is
	// why a separate strict resolver is required.
	if got := canonicalRegisterTransport("garbage"); got != "tcp" {
		t.Fatalf("canonicalRegisterTransport(%q) = %q; the premise of this test changed", "garbage", got)
	}

	for _, tc := range []struct {
		name    string
		mode    string
		want    string
		wantErr bool
	}{
		{name: "udp", mode: "udp", want: protectedTransportUDP},
		{name: "tcp", mode: "tcp", want: protectedTransportTCP},
		{name: "udp_mixed_case", mode: "UDP", want: protectedTransportUDP},
		{name: "tcp_padded", mode: " tcp ", want: protectedTransportTCP},
		{name: "empty", mode: "", wantErr: true},
		{name: "auto_unresolved", mode: "auto", wantErr: true},
		{name: "unknown", mode: "garbage", wantErr: true},
		{name: "sctp", mode: "sctp", wantErr: true},
		{name: "tls", mode: "tls", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveProtectedTransport(tc.mode)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveProtectedTransport(%q) succeeded as %q; it must fail closed", tc.mode, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveProtectedTransport(%q): %v", tc.mode, err)
			}
			if got != tc.want {
				t.Fatalf("resolveProtectedTransport(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// C1.1: the decision itself, driven only by derived sizes.
// ---------------------------------------------------------------------------

// The two thresholds are independent: RFC 3261 clause 18.1.1 is about the SIP
// message, the ESP budget is about the packet the tunnel writer sees. Either one
// alone must select TCP.
func TestLargeProtectedRegisterSelectsTCPBeforeAnyProtectedUDPWrite(t *testing.T) {
	autoCfg := syntheticProtectedRegisterConfig() // 3gpp-default
	for _, tc := range []struct {
		name       string
		configured string
		sipLen     int
		want       string
		reason     string
	}{
		// RFC 3261 clause 18.1.1 boundary.
		//
		// Both thresholds fire well before 1300 here, because the ESP budget is
		// the TIGHTER of the two: a SIP body of 1191 already frames to a 1292 byte
		// packet. So 1300 is TCP via the ESP rule, not UDP. Only past 1301 does the
		// RFC rule also apply, and it is reported in preference because a request
		// that large on UDP is a standards violation regardless of our framing.
		{name: "auto_sip_1300", configured: "auto", sipLen: 1300, want: protectedTransportTCP, reason: protectedTransportReasonESPOverBudget},
		{name: "auto_sip_1301", configured: "auto", sipLen: 1301, want: protectedTransportTCP, reason: protectedTransportReasonSIPOverUDPLimit},

		// ESP budget boundary, expressed in SIP length: the largest SIP body whose
		// UDP-framed ESP packet still fits, and one byte more. This is the real
		// UDP/TCP switchover point.
		{name: "auto_packet_at_budget", configured: "auto", sipLen: protectedRegisterMaxUnfragmentedSIPLen, want: protectedTransportUDP, reason: protectedTransportReasonFits},
		{name: "auto_packet_over_budget", configured: "auto", sipLen: protectedRegisterMaxUnfragmentedSIPLen + 1, want: protectedTransportTCP, reason: protectedTransportReasonESPOverBudget},

		// Explicit configuration always wins, in both directions, at any size.
		{name: "explicit_udp_small", configured: "udp", sipLen: 500, want: protectedTransportUDP, reason: protectedTransportReasonExplicit},
		{name: "explicit_udp_huge", configured: "udp", sipLen: 4000, want: protectedTransportUDP, reason: protectedTransportReasonExplicit},
		{name: "explicit_tcp_small", configured: "tcp", sipLen: 100, want: protectedTransportTCP, reason: protectedTransportReasonExplicit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := decideProtectedRegisterTransport(autoCfg, tc.configured, tc.sipLen)
			if err != nil {
				t.Fatalf("decideProtectedRegisterTransport: %v", err)
			}
			if plan.Transport != tc.want {
				t.Fatalf("transport = %q, want %q", plan.Transport, tc.want)
			}
			if plan.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", plan.Reason, tc.reason)
			}
			// The auto rule must never leave an over-budget packet on UDP. An
			// EXPLICIT udp choice may: the operator asked for it, and the recorded
			// prediction is how that cost stays visible. Silently overriding an
			// explicit setting would be worse than honouring it.
			if plan.Reason == protectedTransportReasonFits &&
				plan.PredictedUDPPacketLen > registerProtectedInnerMTU {
				t.Fatalf("the auto rule selected UDP with a predicted packet of %d over the %d budget",
					plan.PredictedUDPPacketLen, registerProtectedInnerMTU)
			}
			t.Logf("MEASURED sip_len=%d predicted_udp_packet_len=%d transport=%s reason=%s",
				tc.sipLen, plan.PredictedUDPPacketLen, plan.Transport, plan.Reason)
		})
	}
}

// A non-3gpp-default template with its own protected payload path must not be
// switched by the auto rule. giffgaff does not even minimise its initial
// REGISTER, and vodafone_uk_23415 serialises its protected request separately.
func TestProtectedTransportAutoIsScopedToTemplatesThatOptIn(t *testing.T) {
	base := syntheticProtectedRegisterConfig()
	oversize := protectedRegisterMaxUnfragmentedSIPLen + 200

	// 3gpp-default opts in.
	plan, err := decideProtectedRegisterTransport(base, "auto", oversize)
	if err != nil {
		t.Fatalf("3gpp-default decide: %v", err)
	}
	if plan.Transport != protectedTransportTCP {
		t.Fatalf("3gpp-default auto transport = %q, want tcp", plan.Transport)
	}

	// Any other template keeps the existing protected UDP behaviour, so this
	// phase cannot regress a carrier that already registers.
	for _, tc := range []struct {
		name     string
		behavior policy.CarrierBehavior
	}{
		{name: "vodafone_uk_23415", behavior: policy.ResolveCarrierBehavior("234", "15")},
		{name: "giffgaff_23410", behavior: policy.ResolveCarrierBehavior("234", "10")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.CarrierBehavior = tc.behavior
			got, err := decideProtectedRegisterTransport(cfg, "auto", oversize)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if got.Transport != protectedTransportUDP {
				t.Fatalf("behavior %q auto transport = %q, want udp (not opted in)", tc.name, got.Transport)
			}
			if got.Reason != protectedTransportReasonTemplateOptOut {
				t.Fatalf("behavior %q reason = %q, want %q", tc.name, got.Reason, protectedTransportReasonTemplateOptOut)
			}
		})
	}
}

// The decision must depend only on the request it is given. A SIP status, a
// timeout or a candidate index must never reach it: that would reintroduce the
// "send UDP, wait, replay on TCP" behaviour RFC 3261 does not define.
func TestProtectedTransportDecisionIsSizeOnly(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	small := 800
	large := protectedRegisterMaxUnfragmentedSIPLen + 1

	first, err := decideProtectedRegisterTransport(cfg, "auto", small)
	if err != nil {
		t.Fatalf("decide small: %v", err)
	}
	// Same input, repeated: the decision has to be a pure function of it.
	for i := 0; i < 3; i++ {
		again, err := decideProtectedRegisterTransport(cfg, "auto", small)
		if err != nil {
			t.Fatalf("decide small repeat %d: %v", i, err)
		}
		if again != first {
			t.Fatal("the decision is not a pure function of its inputs")
		}
	}
	bigger, err := decideProtectedRegisterTransport(cfg, "auto", large)
	if err != nil {
		t.Fatalf("decide large: %v", err)
	}
	if bigger.Transport == first.Transport {
		t.Fatal("size did not change the decision; the rule is not size-driven")
	}
	// A negative or absurd length must fail closed rather than default to UDP.
	if _, err := decideProtectedRegisterTransport(cfg, "auto", -1); err == nil {
		t.Fatal("a negative SIP length was accepted")
	}
	if _, err := decideProtectedRegisterTransport(cfg, "auto", 0); err == nil {
		t.Fatal("a zero SIP length was accepted")
	}
}

// ---------------------------------------------------------------------------
// C1.2: the preview must not mutate anything or burn a second AKA vector.
// ---------------------------------------------------------------------------

// buildAuthenticatedRegister only runs AKA when the challenged request carries
// no Authorization header, reusing the already-computed value otherwise. So the
// way to prove no second vector is consumed is structural: the challenged
// request must still carry its Authorization afterwards, and cfg.AKA is left nil
// here so any attempt to run AKA would panic or error rather than pass quietly.
func TestProtectedTransportPreviewDoesNotAdvanceCSeqOrRecomputeAKA(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	challenge := syntheticChallengeResponse(t)
	// The protected ports only exist once the SA is installed, which is exactly
	// the ordering production uses: 401 -> install -> decide -> build.
	if err := installIPSecFromChallenge(cfg, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	challenged := syntheticChallengedRequest(t, cfg, state)

	// Snapshot the challenged request before anything touches it.
	beforeCSeq := headerValueForTest(challenged, "CSeq")
	beforeCallID := headerValueForTest(challenged, "Call-ID")
	beforeAuth := headerValueForTest(challenged, "Authorization")
	beforeSecClient := headerValueForTest(challenged, "Security-Client")
	beforeSerialized := challenged.String()

	// Build the transport-neutral base request ONCE.
	base, _, err := buildAuthenticatedRegister(cfg, *state, challenged, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	baseCSeq := headerValueForTest(base, "CSeq")

	// The preview must work on a clone and must not disturb the base.
	previewLen, err := previewProtectedRegisterUDPLen(cfg, *state, base)
	if err != nil {
		t.Fatalf("previewProtectedRegisterUDPLen: %v", err)
	}
	if previewLen <= 0 {
		t.Fatalf("preview length = %d, want positive", previewLen)
	}

	// 1. The challenged request is untouched.
	if got := challenged.String(); got != beforeSerialized {
		t.Fatal("the challenged request was mutated by the protected transport preview")
	}
	if headerValueForTest(challenged, "CSeq") != beforeCSeq {
		t.Fatal("the challenged request CSeq changed")
	}
	if headerValueForTest(challenged, "Call-ID") != beforeCallID {
		t.Fatal("the challenged request Call-ID changed")
	}
	if headerValueForTest(challenged, "Authorization") != beforeAuth {
		t.Fatal("the challenged request Authorization changed")
	}
	if headerValueForTest(challenged, "Security-Client") != beforeSecClient {
		t.Fatal("the challenged request Security-Client changed")
	}

	// 2. The base request is untouched: no Via, no CSeq bump, no Contact rewrite.
	if got := headerValueForTest(base, "CSeq"); got != baseCSeq {
		t.Fatal("the preview advanced the base request CSeq")
	}
	if base.GetHeader("Via") != nil {
		t.Fatal("the preview added a Via to the base request")
	}

	// 3. Building the final request advances CSeq exactly once, from the base.
	plan, err := decideProtectedRegisterTransport(cfg, "auto", previewLen)
	if err != nil {
		t.Fatalf("decideProtectedRegisterTransport: %v", err)
	}
	final, err := buildFinalProtectedRegisterRequest(cfg, *state, base, plan.Transport)
	if err != nil {
		t.Fatalf("buildFinalProtectedRegisterRequest: %v", err)
	}
	wantCSeq, err := expectedNextCSeqForTest(baseCSeq)
	if err != nil {
		t.Fatal(err)
	}
	if got := headerValueForTest(final, "CSeq"); got != wantCSeq {
		t.Fatalf("final CSeq did not advance exactly once")
	}
	// 4. Call-ID must be carried through unchanged: TS 24.229 clause 5.1.1.5.1
	// requires the protected REGISTER to reuse the challenge's Call-ID.
	if headerValueForTest(final, "Call-ID") != beforeCallID {
		t.Fatal("the final protected request changed Call-ID")
	}
	// 5. Security-Client must be byte-identical (TS 33.203 Annex H rule 3).
	if headerValueForTest(final, "Security-Client") != beforeSecClient {
		t.Fatal("the final protected request changed Security-Client")
	}
	// 6. Security-Verify must mirror the negotiated offer.
	if state.verifyHeader != "" &&
		headerValueForTest(final, "Security-Verify") != state.verifyHeader {
		t.Fatal("the final protected request does not mirror Security-Verify")
	}

	// 7. Building the final request twice from the same base must be
	// deterministic in CSeq: the base is the only source of truth.
	second, err := buildFinalProtectedRegisterRequest(cfg, *state, base, plan.Transport)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if headerValueForTest(second, "CSeq") != wantCSeq {
		t.Fatal("a second build produced a different CSeq; the base was mutated")
	}

	t.Logf("MEASURED preview_len=%d transport=%s cseq_advanced_once=true callid_stable=true",
		previewLen, plan.Transport)
}

// The transport-neutral base must not carry any transport-specific header, or
// the final request would inherit UDP artefacts on a TCP send.
func TestProtectedRegisterBaseRequestIsTransportNeutral(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	challenge := syntheticChallengeResponse(t)
	if err := installIPSecFromChallenge(cfg, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	challenged := syntheticChallengedRequest(t, cfg, state)

	base, _, err := buildAuthenticatedRegister(cfg, *state, challenged, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	if base.GetHeader("Via") != nil {
		t.Fatal("the base request carries a Via; it must be added per transport")
	}

	// Each transport produces its own final request from the same base.
	udpReq, err := buildFinalProtectedRegisterRequest(cfg, *state, base, protectedTransportUDP)
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	tcpReq, err := buildFinalProtectedRegisterRequest(cfg, *state, base, protectedTransportTCP)
	if err != nil {
		t.Fatalf("build tcp: %v", err)
	}

	udpVia := headerValueForTest(udpReq, "Via")
	tcpVia := headerValueForTest(tcpReq, "Via")
	if !strings.Contains(strings.ToUpper(udpVia), "SIP/2.0/UDP") {
		t.Fatal("the UDP request Via does not carry the UDP transport token")
	}
	if !strings.Contains(strings.ToUpper(tcpVia), "SIP/2.0/TCP") {
		t.Fatal("the TCP request Via does not carry the TCP transport token")
	}
	// RFC 3261 clause 18.1.1: the Via transport MUST change with the transport.
	if strings.Contains(strings.ToUpper(tcpVia), "SIP/2.0/UDP") {
		t.Fatal("the TCP request Via still claims UDP")
	}
	// TS 24.229 clause 5.1.1.2.1 d): rport is a UDP-only artefact.
	if strings.Contains(strings.ToLower(tcpVia), "rport") {
		t.Fatal("the TCP request Via carries rport, which is UDP-only")
	}
	if !strings.Contains(strings.ToLower(udpVia), "rport") {
		t.Fatal("the UDP request Via lost rport; existing behaviour changed")
	}
	if got := strings.ToUpper(strings.TrimSpace(tcpReq.Transport())); got != "TCP" {
		t.Fatalf("tcp request transport = %q, want TCP", got)
	}
	if got := strings.ToUpper(strings.TrimSpace(udpReq.Transport())); got != "UDP" {
		t.Fatalf("udp request transport = %q, want UDP", got)
	}
	// Both must still target the negotiated protected server port of the P-CSCF.
	if udpReq.Destination() != tcpReq.Destination() {
		t.Fatal("the two transports disagree on the protected destination")
	}
	t.Logf("MEASURED base_has_via=false udp_via_has_rport=true tcp_via_has_rport=false")
}

// ---------------------------------------------------------------------------
// small helpers, test-local
// ---------------------------------------------------------------------------

func headerValueForTest(req *sip.Request, name string) string {
	if req == nil {
		return ""
	}
	h := req.GetHeader(name)
	if h == nil {
		return ""
	}
	return strings.TrimSpace(h.Value())
}

func expectedNextCSeqForTest(baseCSeq string) (string, error) {
	fields := strings.Fields(baseCSeq)
	if len(fields) != 2 {
		return "", errCSeqShapeForTest
	}
	var n int
	for _, r := range fields[0] {
		if r < '0' || r > '9' {
			return "", errCSeqShapeForTest
		}
		n = n*10 + int(r-'0')
	}
	return itoaForTest(n+1) + " " + fields[1], nil
}

var errCSeqShapeForTest = errShape("unexpected CSeq shape")

type errShape string

func (e errShape) Error() string { return string(e) }

func itoaForTest(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}
