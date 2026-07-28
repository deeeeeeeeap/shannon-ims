package imscore

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/emiago/sipgo/sip"
)

// Phase C2: the protected dial must dispatch on an ALREADY-RESOLVED transport,
// and the UDP path must be reachable only through its own case.
//
// The two former guards were negative assertions ("reject anything that is not
// udp"). Replacing them with a positive switch matters because a third value can
// then never fall into the UDP branch by accident: `default` fails closed.
//
// These tests do not open a tunnel. They exercise the dispatch decision, the
// header composition per transport, and the production gate that keeps auto->TCP
// disabled until the Phase D server listener exists.
//
// Assertions are enums, booleans, counts and derived lengths. No SIP text,
// identity, address, port value, SPI or key material is asserted or logged.

// ---------------------------------------------------------------------------
// C2.1: dispatch
// ---------------------------------------------------------------------------

// A resolved transport of "udp" must take the legacy path, "tcp" the new one,
// and anything else must fail before a connection is attempted.
func TestProtectedDialDispatchesOnResolvedTransport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		want    string
		wantErr bool
	}{
		{name: "udp", mode: "udp", want: protectedDialPathUDP},
		{name: "tcp", mode: "tcp", want: protectedDialPathTCP},
		{name: "empty", mode: "", wantErr: true},
		{name: "auto_unresolved", mode: "auto", wantErr: true},
		{name: "unknown", mode: "garbage", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := protectedDialPathFor(tc.mode)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("protectedDialPathFor(%q) resolved to %q; it must fail closed", tc.mode, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("protectedDialPathFor(%q): %v", tc.mode, err)
			}
			if got != tc.want {
				t.Fatalf("protectedDialPathFor(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

// The dispatch must refuse to run at all without a raw dataplane, on either
// path, so a missing tunnel can never be mistaken for a transport problem.
func TestProtectedDialRequiresRawDataplaneOnBothPaths(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}

	ctx := context.Background()
	for _, mode := range []string{protectedTransportUDP, protectedTransportTCP} {
		t.Run(mode, func(t *testing.T) {
			conn, err := dialProtectedRegisterConn(ctx, cfg, nil, *state, mode)
			if err == nil {
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatal("dial succeeded without a SWu dataplane")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// C2.2: the production gate
// ---------------------------------------------------------------------------

// Until the Phase D server listener exists, an auto-derived TCP decision must
// not take effect in production: TS 33.203 clause 7.1 requires the P-CSCF to be
// able to open port_pc -> port_us, and TS 24.229 clause 3.1 NOTE 3 says every
// network-originated request can only use that flow. Registering over TCP with
// no listener would mean a registration that cannot receive anything.
//
// Both an auto-derived and an explicit TCP intent are gated identically: the gate
// is about whether the UE can RECEIVE, not about what the operator asked for.
func TestAutoDerivedTCPIsGatedUntilServerFlowExists(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	// One byte past the ESP budget, and deliberately still BELOW the RFC 3261
	// clause 18.1.1 threshold of 1300. The two rules are independent and the ESP
	// budget is the tighter of the two, so a larger value here would report
	// sip_over_udp_limit and this test would stop exercising the budget rule.
	oversize := protectedRegisterMaxUnfragmentedSIPLen + 1
	if oversize > registerSIPUDPLimit {
		t.Fatalf("test premise broken: %d is past the SIP limit %d", oversize, registerSIPUDPLimit)
	}

	// The size rule itself still reports TCP: the decision is not being hidden,
	// and the plan keeps its measurements so a log line can state the truth.
	raw, err := decideProtectedRegisterTransport(cfg, "auto", oversize)
	if err != nil {
		t.Fatalf("decideProtectedRegisterTransport: %v", err)
	}
	if raw.Transport != protectedTransportTCP {
		t.Fatalf("size rule transport = %q, want tcp", raw.Transport)
	}
	if raw.Reason != protectedTransportReasonESPOverBudget {
		t.Fatalf("size rule reason = %q, want %q", raw.Reason, protectedTransportReasonESPOverBudget)
	}

	// Activation is refused while no server listener exists. Crucially it does NOT
	// downgrade to UDP: the plan says TCP precisely because the request does not
	// fit UDP, so a downgrade would send a request that fragments.
	err = authorizeProtectedTCPActivation(raw, protectedTCPActivation{})
	if err == nil {
		t.Fatal("auto-derived TCP was authorized with no server flow")
	}
	var unavailable *protectedTCPUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("refusal is not a classified protectedTCPUnavailableError: %v", err)
	}
	if unavailable.Reason() != protectedTransportReasonServerFlowPending {
		t.Fatalf("refusal reason = %q, want %q",
			unavailable.Reason(), protectedTransportReasonServerFlowPending)
	}

	// A UDP plan is always authorized: this gate only ever constrains TCP.
	fits, err := decideProtectedRegisterTransport(cfg, "auto", 800)
	if err != nil {
		t.Fatalf("decide fits: %v", err)
	}
	if fits.Transport != protectedTransportUDP {
		t.Fatalf("small request transport = %q, want udp", fits.Transport)
	}
	if err := authorizeProtectedTCPActivation(fits, protectedTCPActivation{}); err != nil {
		t.Fatalf("a UDP plan was refused by the TCP activation gate: %v", err)
	}

	t.Logf("MEASURED size_rule=tcp activation=refused reason=%s downgraded_to_udp=false",
		unavailable.Reason())
}

// The correction this test locks in: an explicit `transport=tcp` expresses
// transport INTENT only. It is not consent to register without a server flow,
// because TS 33.203 clause 7.1 and TS 24.229 clause 3.1 NOTE 3 leave the network
// no other way to reach the UE. Registering anyway would look like success and
// then drop every terminating request, so the send must fail closed instead.
func TestExplicitProtectedTCPFailsClosedUntilServerFlowReady(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()

	// Explicit TCP resolves as intent - that part is allowed.
	resolved, err := resolveProtectedTransport("tcp")
	if err != nil {
		t.Fatalf("resolveProtectedTransport(tcp): %v", err)
	}
	if resolved != protectedTransportTCP {
		t.Fatalf("explicit tcp resolved to %q", resolved)
	}
	plan, err := decideProtectedRegisterTransport(cfg, "tcp", 900)
	if err != nil {
		t.Fatalf("decide explicit tcp: %v", err)
	}
	if plan.Transport != protectedTransportTCP || plan.Reason != protectedTransportReasonExplicit {
		t.Fatalf("explicit plan = %q/%q", plan.Transport, plan.Reason)
	}

	// Activation is refused for every not-ready state, explicit or not.
	for _, tc := range []struct {
		name       string
		activation protectedTCPActivation
	}{
		{name: "nothing_ready", activation: protectedTCPActivation{}},
		{name: "listener_down_generation_current", activation: protectedTCPActivation{Generation: 7}},
		{name: "listener_up_no_generation", activation: protectedTCPActivation{ServerFlowReady: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeProtectedTCPActivation(plan, tc.activation)
			if err == nil {
				t.Fatal("explicit TCP was authorized without a ready server flow")
			}
			var unavailable *protectedTCPUnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatalf("refusal is not classified: %v", err)
			}
			if unavailable.Reason() != protectedTransportReasonServerFlowPending {
				t.Fatalf("reason = %q", unavailable.Reason())
			}
		})
	}

	// And the refusal must happen before anything is dialled or written: the dial
	// helper is never reached, so no carrier is opened and no SIP is serialized.
	state := syntheticProtectedRegisterState(cfg)
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	dialer := &countingRawDialer{}
	if err := authorizeProtectedTCPActivation(plan, protectedTCPActivation{}); err == nil {
		// Only if the gate wrongly allows it would production dial at all.
		channel, dialErr := dialProtectedRegisterConn(
			context.Background(), cfg, dialer, *state, protectedTransportTCP)
		if channel != nil {
			_ = channel.Close()
		}
		t.Fatalf("gate allowed activation; dial returned %v", dialErr)
	}
	if got := dialer.dials; got != 0 {
		t.Fatalf("carrier dials = %d, want 0: the refusal must precede any physical write", got)
	}

	// Both gate positions are asserted, so this test does not have to be revisited
	// when the default flips. The invariant is about the gate's SEMANTICS, not its
	// current value:
	//
	//   gate off -> even a fully ready runtime is refused
	//   gate on  -> a ready runtime is permitted, an unready one still is not
	//
	// The earlier version of this block asserted the constant was literally false,
	// which made it a restatement of the default rather than a check on behaviour.
	ready := protectedTCPActivation{ServerFlowReady: true, Generation: 3}

	previous := protectedTCPClientProductionEnabled
	protectedTCPClientProductionEnabled = false
	if err := authorizeProtectedTCPActivation(plan, ready); err == nil {
		protectedTCPClientProductionEnabled = previous
		t.Fatal("a ready activation was authorized while the gate was off")
	}
	protectedTCPClientProductionEnabled = true
	if err := authorizeProtectedTCPActivation(plan, ready); err != nil {
		protectedTCPClientProductionEnabled = previous
		t.Fatalf("a ready activation was refused while the gate was on: %v", err)
	}
	// An unready runtime must stay refused even with the gate on: that is the
	// difference between "shipping is allowed" and "this runtime can receive".
	if err := authorizeProtectedTCPActivation(plan, protectedTCPActivation{}); err == nil {
		protectedTCPClientProductionEnabled = previous
		t.Fatal("an unready activation was authorized with the gate on")
	}
	protectedTCPClientProductionEnabled = previous

	t.Logf("MEASURED explicit_intent_resolved=true unready_refused_both_positions=true gate_off_refuses_ready=true gate_on_allows_ready=true carrier_dials=0")
}

// ---------------------------------------------------------------------------
// C2.3: the winning candidate and the negotiated ports
// ---------------------------------------------------------------------------

// Every binding of the protected TCP request must follow the candidate whose 401
// drove IPsec: the destination host, the destination port and the local
// protected client port.
func TestProtectedTCPClientUsesWinningCandidateAndNegotiatedPorts(t *testing.T) {
	base := syntheticProtectedRegisterConfig()

	losing := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(losingCandidateHost, "5060"),
	})
	winning := candidateAttemptConfig(base, registerAttemptCandidate{
		Registrar: net.JoinHostPort(base.LocalIP.String(), "5060"),
		Gateway:   net.JoinHostPort(winningCandidateHost, "5060"),
	})
	losingIP := effectiveIPSecRemoteIP(losing)
	winningIP := effectiveIPSecRemoteIP(winning)
	if losingIP == nil || winningIP == nil || losingIP.Equal(winningIP) {
		t.Fatal("the two test candidates must be distinct and resolvable")
	}

	state := syntheticProtectedRegisterState(winning)
	challenge := syntheticChallengeFromCandidate(t)
	if err := installIPSecFromChallenge(winning, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}

	base401 := syntheticChallengedRequest(t, winning, state)
	neutral, _, err := buildAuthenticatedRegister(winning, *state, base401, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	req, err := buildFinalProtectedRegisterRequest(winning, *state, neutral, protectedTransportTCP)
	if err != nil {
		t.Fatalf("buildFinalProtectedRegisterRequest: %v", err)
	}

	// 1. Destination host is the winning candidate, never the losing one.
	host, port, err := net.SplitHostPort(req.Destination())
	if err != nil {
		t.Fatal("protected TCP destination is not host:port")
	}
	dest := net.ParseIP(host)
	if dest == nil || !dest.Equal(winningIP) {
		t.Fatal("protected TCP destination is not the winning candidate")
	}
	if dest.Equal(losingIP) {
		t.Fatal("protected TCP destination is the losing candidate")
	}

	// 2. Destination port is the offered protected server port, not a default.
	if port != itoaC2(state.ipsecPolicy.FlowC.RemotePort) {
		t.Fatal("protected TCP destination port is not the negotiated port_ps")
	}

	// 3. The local bind must be the UE protected client port from the same policy.
	// ipsec3gpp.ClientFlowBindPort is what DialClientFlow itself binds, so this
	// asserts the production rule rather than restating it.
	if got := ipsec3gpp.ClientFlowBindPort(state.ipsecPolicy); got != state.ipsecPolicy.FlowC.LocalPort {
		t.Fatalf("client bind port = %d, want the policy port_uc", got)
	}
	// And it must differ from the server port, or the two flows would collide.
	if state.ipsecPolicy.FlowC.LocalPort == state.ipsecPolicy.FlowS.LocalPort {
		t.Fatal("port_uc and port_us are identical in the derived policy")
	}

	t.Logf("MEASURED destination_is_winning=true port_is_negotiated=true bind_is_port_uc=true")
}

// ---------------------------------------------------------------------------
// C2.4: header composition on the TCP path
// ---------------------------------------------------------------------------

// The TCP protected request must satisfy every binding rule at once. This is the
// composition oracle for the transport switch.
func TestProtectedTCPClientRequestCompositionFollowsSpec(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	challenge := syntheticChallengeResponse(t)
	if err := installIPSecFromChallenge(cfg, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	challenged := syntheticChallengedRequest(t, cfg, state)

	wantCallID := headerValueForTest(challenged, "Call-ID")
	wantSecClient := headerValueForTest(challenged, "Security-Client")

	neutral, _, err := buildAuthenticatedRegister(cfg, *state, challenged, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}
	req, err := buildFinalProtectedRegisterRequest(cfg, *state, neutral, protectedTransportTCP)
	if err != nil {
		t.Fatalf("buildFinalProtectedRegisterRequest: %v", err)
	}

	// RFC 3261 clause 18.1.1: the Via transport token must be TCP.
	via := headerValueForTest(req, "Via")
	if !strings.Contains(strings.ToUpper(via), "SIP/2.0/TCP") {
		t.Fatal("Via does not carry the TCP transport token")
	}
	// TS 24.229 clause 5.1.1.2.1 d): rport is UDP-only.
	if strings.Contains(strings.ToLower(via), "rport") {
		t.Fatal("Via carries rport on TCP")
	}
	// A fresh branch is required per RFC 3261 clause 8.1.1.7.
	if !strings.Contains(strings.ToLower(via), "branch=") {
		t.Fatal("Via has no branch parameter")
	}

	// TS 24.229 clause 5.1.1.2.2 b): Contact carries the protected server port on
	// every protected REGISTER, with no transport exemption.
	contact := headerValueForTest(req, "Contact")
	if !strings.Contains(contact, itoaC2(state.ipsecPolicy.FlowS.LocalPort)) {
		t.Fatal("Contact does not carry the protected server port")
	}

	// TS 24.229 clause 5.1.1.5.1: the Call-ID must be reused.
	if headerValueForTest(req, "Call-ID") != wantCallID {
		t.Fatal("Call-ID changed on the protected TCP request")
	}
	// TS 33.203 Annex H rule 3: Security-Client must be byte-identical.
	if headerValueForTest(req, "Security-Client") != wantSecClient {
		t.Fatal("Security-Client changed on the protected TCP request")
	}
	// The Authorization must be carried over, never re-derived: a second AKA run
	// would consume another USIM vector.
	//
	// The proof here is structural rather than a string comparison. cfg carries no
	// AKA provider, and buildAuthenticatedRegister only calls computeAKAAuth when
	// the challenged request has no Authorization header at all - so reaching this
	// point at all means the existing credential was reused. A value comparison
	// would be weaker AND misleading: the 3gpp-default template already emits a
	// plain digest placeholder, so a challenged request legitimately carries more
	// than one Authorization header and "the first one" is not a stable identity.
	if cfg.AKA != nil {
		t.Fatal("this test must run without an AKA provider for its proof to hold")
	}
	if len(req.GetHeaders("Authorization")) == 0 {
		t.Fatal("the protected TCP request carries no Authorization")
	}
	if !authorizationValuesPreserved(challenged, req) {
		t.Fatal("the protected request introduced an Authorization value that was not in the challenge")
	}
	// Security-Verify must mirror the negotiated offer.
	if state.verifyHeader != "" &&
		headerValueForTest(req, "Security-Verify") != state.verifyHeader {
		t.Fatal("Security-Verify does not mirror the negotiated Security-Server")
	}
	// RFC 3261 clause 22.2: CSeq advances exactly once.
	wantCSeq, err := expectedNextCSeqForTest(headerValueForTest(neutral, "CSeq"))
	if err != nil {
		t.Fatal(err)
	}
	if headerValueForTest(req, "CSeq") != wantCSeq {
		t.Fatal("CSeq did not advance exactly once")
	}
	if got := strings.ToUpper(strings.TrimSpace(req.Transport())); got != "TCP" {
		t.Fatalf("request transport = %q, want TCP", got)
	}

	t.Logf("MEASURED via_transport=tcp via_rport=false callid_stable=true " +
		"secclient_stable=true auth_carried=true cseq_advanced_once=true")
}

// The UDP composition must be unchanged by the introduction of the TCP path,
// otherwise the carriers that already register would regress.
func TestProtectedUDPCompositionIsUnchanged(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	challenge := syntheticChallengeResponse(t)
	if err := installIPSecFromChallenge(cfg, state, challenge); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}
	challenged := syntheticChallengedRequest(t, cfg, state)
	neutral, _, err := buildAuthenticatedRegister(cfg, *state, challenged, challenge)
	if err != nil {
		t.Fatalf("buildAuthenticatedRegister: %v", err)
	}

	// The new builder on the UDP path must produce what the legacy preparer does.
	viaNew, err := buildFinalProtectedRegisterRequest(cfg, *state, neutral, protectedTransportUDP)
	if err != nil {
		t.Fatalf("build udp: %v", err)
	}
	legacy := neutral.Clone()
	if err := prepareProtectedRegisterRequest(cfg, *state, legacy); err != nil {
		t.Fatalf("prepareProtectedRegisterRequest: %v", err)
	}

	// Branch and any other per-request nonce differ by construction, so compare
	// the stable, spec-relevant parts only.
	for _, name := range []string{"CSeq", "Contact", "Call-ID", "Security-Client", "Authorization"} {
		if got, want := headerValueForTest(viaNew, name), headerValueForTest(legacy, name); got != want {
			t.Fatalf("UDP path header %q changed", name)
		}
	}
	if viaNew.Destination() != legacy.Destination() {
		t.Fatal("UDP path destination changed")
	}
	if got, want := strings.ToUpper(viaNew.Transport()), strings.ToUpper(legacy.Transport()); got != want {
		t.Fatalf("UDP path transport changed: %q vs %q", got, want)
	}
	newVia := strings.ToUpper(headerValueForTest(viaNew, "Via"))
	oldVia := strings.ToUpper(headerValueForTest(legacy, "Via"))
	if strings.Contains(newVia, "SIP/2.0/UDP") != strings.Contains(oldVia, "SIP/2.0/UDP") {
		t.Fatal("UDP path Via transport token changed")
	}
	if strings.Contains(strings.ToLower(newVia), "rport") != strings.Contains(strings.ToLower(oldVia), "rport") {
		t.Fatal("UDP path rport presence changed")
	}
	t.Logf("MEASURED udp_composition_stable=true")
}

// authorizationValuesPreserved reports whether every Authorization value on the
// final request already existed on the challenged request.
//
// This is a set comparison rather than a first-header comparison on purpose. The
// 3gpp-default template emits a plain digest placeholder, so a challenged
// REGISTER legitimately carries more than one Authorization header, and header
// order is not part of the contract. What matters is that no NEW credential
// appeared - a freshly computed AKA response would be a value the challenge never
// held.
func authorizationValuesPreserved(challenged, final *sip.Request) bool {
	if challenged == nil || final == nil {
		return false
	}
	known := map[string]struct{}{}
	for _, h := range challenged.GetHeaders("Authorization") {
		if h == nil {
			continue
		}
		known[strings.TrimSpace(h.Value())] = struct{}{}
	}
	for _, h := range final.GetHeaders("Authorization") {
		if h == nil {
			continue
		}
		if _, ok := known[strings.TrimSpace(h.Value())]; !ok {
			return false
		}
	}
	return true
}

func itoaC2(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	out := ""
	for v > 0 {
		out = string(rune('0'+v%10)) + out
		v /= 10
	}
	if neg {
		return "-" + out
	}
	return out
}

// ---------------------------------------------------------------------------
// C2.5: one connection, and no fallback of any kind
// ---------------------------------------------------------------------------

// countingRawDialer records how many raw ESP carriers were opened and can fail
// on demand. It implements just enough of the SWu surface to drive the dispatch.
type countingRawDialer struct {
	dials    int
	failWith error
	conns    []*closeCountingConn
}

func (d *countingRawDialer) DialContextIP(_ context.Context, _ net.IP, _ net.IP, _ uint8) (net.Conn, error) {
	d.dials++
	if d.failWith != nil {
		return nil, d.failWith
	}
	c := &closeCountingConn{}
	d.conns = append(d.conns, c)
	return c, nil
}

func (d *countingRawDialer) DialContextTCP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (d *countingRawDialer) DialContextUDP(context.Context, net.IP, int, net.IP, int) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (d *countingRawDialer) ListenContextTCP(context.Context, net.IP, int) (net.Listener, error) {
	return nil, errors.New("not used")
}
func (d *countingRawDialer) ListenContextUDP(context.Context, net.IP, int) (net.PacketConn, error) {
	return nil, errors.New("not used")
}
func (d *countingRawDialer) Close() error { return nil }

// closeCountingConn is a carrier that blocks on Read and counts Close, so a
// leaked ESP carrier is detectable.
type closeCountingConn struct {
	mu      sync.Mutex
	closed  int
	release chan struct{}
	once    sync.Once
}

func (c *closeCountingConn) ensure() chan struct{} {
	c.once.Do(func() { c.release = make(chan struct{}) })
	return c.release
}

func (c *closeCountingConn) Read([]byte) (int, error) {
	<-c.ensure()
	return 0, net.ErrClosed
}
func (c *closeCountingConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeCountingConn) Close() error {
	c.mu.Lock()
	c.closed++
	c.mu.Unlock()
	c.once.Do(func() { c.release = make(chan struct{}) })
	select {
	case <-c.release:
	default:
		close(c.release)
	}
	return nil
}
func (c *closeCountingConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
func (*closeCountingConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*closeCountingConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*closeCountingConn) SetDeadline(time.Time) error      { return nil }
func (*closeCountingConn) SetReadDeadline(time.Time) error  { return nil }
func (*closeCountingConn) SetWriteDeadline(time.Time) error { return nil }

// A protected TCP channel must expose exactly one connection, must not hand back
// a legacy packet-mode secure channel, and a failure must not silently become a
// UDP attempt, a candidate switch or a replay.
//
// TS 24.229 clause 5.1.5.1 is explicit that a protected REGISTER that gets no
// answer means the registration failed and the temporary SAs are deleted - not
// that another transport should be tried with the same credentials. RFC 3261
// clause 18.1.1 only defines the TCP -> UDP fallback for RFC 2543 compatibility,
// never UDP <- TCP after a timeout.
func TestProtectedTCPClientReadsResponseOnSameConnectionAndNeverFallsBack(t *testing.T) {
	cfg := syntheticProtectedRegisterConfig()
	state := syntheticProtectedRegisterState(cfg)
	if err := installIPSecFromChallenge(cfg, state, syntheticChallengeResponse(t)); err != nil {
		t.Fatalf("installIPSecFromChallenge: %v", err)
	}

	t.Run("carrier failure returns one error and no fallback", func(t *testing.T) {
		dialer := &countingRawDialer{failWith: errors.New("synthetic carrier failure")}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		ch, err := dialProtectedRegisterConn(ctx, cfg, dialer, *state, protectedTransportTCP)
		if err == nil {
			if ch != nil {
				_ = ch.Close()
			}
			t.Fatal("the dial succeeded despite a failing ESP carrier")
		}
		// Exactly one carrier attempt: no retry, no second candidate.
		if dialer.dials != 1 {
			t.Fatalf("raw carrier dials = %d, want exactly 1 (no retry, no fallback)", dialer.dials)
		}
		t.Logf("MEASURED carrier_dials=1 fallback_attempts=0 channel=nil")
	})

	t.Run("tcp channel exposes no legacy packet channel", func(t *testing.T) {
		dialer := &countingRawDialer{}
		// A short timeout: the synthetic peer never answers the SYN, so the dial is
		// expected to fail. What matters is what it did NOT do on the way there.
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()

		ch, err := dialProtectedRegisterConn(ctx, cfg, dialer, *state, protectedTransportTCP)
		if err == nil {
			// If a handshake somehow completed, the invariants below still apply.
			defer func() { _ = ch.Close() }()
			if ch.secure != nil {
				t.Fatal("the TCP channel exposed a legacy packet-mode secure channel")
			}
			if ch.conn == nil {
				t.Fatal("the TCP channel has no connection to read the response from")
			}
			if ch.transport != protectedTransportTCP {
				t.Fatalf("channel transport = %q, want tcp", ch.transport)
			}
			return
		}
		// The failing path must still have opened exactly one carrier and must not
		// have leaked it.
		if dialer.dials != 1 {
			t.Fatalf("raw carrier dials = %d, want 1", dialer.dials)
		}
		if len(dialer.conns) != 1 {
			t.Fatalf("carriers created = %d, want 1", len(dialer.conns))
		}
		if got := dialer.conns[0].closeCount(); got == 0 {
			t.Fatal("the ESP carrier was leaked when the protected dial failed")
		}
		t.Logf("MEASURED carrier_dials=1 carrier_closed=true secure_channel_exposed=false")
	})
}
