package imscore

import (
	"context"
	"fmt"
	"net"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// Phase C2: dispatch the protected REGISTER onto the transport that was decided
// BEFORE the request was built.
//
// The two pre-existing guards in dialSecureRegisterConn and
// prepareProtectedRegisterRequest rejected everything that was not UDP. Deleting
// them would leave the legacy path protected by nothing, and would let the
// synthetic-header TCP channel (buildMinimalTCPSegment: fixed seq/ack, no
// checksum, no segmentation) become reachable from production for the first
// time. So instead of relaxing a negation, this file dispatches on a closed set:
//
//	udp     -> the existing WrapSecureChannelUDP path, byte for byte
//	tcp     -> a real gvisor TCP stack over the protected link endpoint
//	anything else -> error
//
// A future third value therefore fails closed instead of silently landing in the
// UDP branch, which is what "not udp" would have done.
//
// protectedTCPClientProductionEnabled is the production gate for the protected
// TCP client flow.
//
// The reason it exists: a UE that dials the protected client port without also
// listening on its protected server port is only half the specification.
// TS 33.203 clause 7.1 requires the P-CSCF to open its own connection to port_us
// for every network-originated request, and TS 24.229 clause 3.1 NOTE 3 says
// downlink requests can use no other flow. Enabling auto->TCP without that
// listener would register successfully and then silently miss every terminating
// INVITE, MESSAGE and NOTIFY.
//
// The listener now exists (startProtectedTCPRuntime returns already listening),
// so what the gate still guards is the one thing offline tests cannot answer:
// whether the P-CSCF actually accepts a protected REGISTER over TCP.
//
// It is a var rather than a const so the enabled path can be exercised in tests
// without shipping it on, and so a test can force it OFF again.
//
// Enabled as of the Phase F controlled reconnect. What this turns on is narrow:
// decideProtectedRegisterTransport only selects TCP for a template that opts in
// (3gpp-default) AND a protected request whose UDP-framed ESP packet would not
// fit the SWu raw IP MTU. Everything else - every other template, every request
// that fits, and any explicit transport=udp - still takes the legacy UDP path
// byte for byte.
//
// A TCP decision is final: it must not fall back to UDP, because the decision was
// made precisely because the request does not fit UDP. A downgrade would put a
// fragmenting request on the wire, which is the failure this path exists to
// remove.
var protectedTCPClientProductionEnabled = true

// protectedRegisterChannel is one protected SIP channel plus everything that has
// to be torn down with it.
//
// secure is populated for UDP only. The rest of the service still reaches for
// it (PacketMode, messaging attach), so the UDP path keeps returning exactly
// what it returned before.
type protectedRegisterChannel struct {
	conn      net.Conn
	secure    *ipsec3gpp.SecureChannelConn
	tcpStack  *ipsec3gpp.ProtectedTCPStack
	transport string
}

// Close releases the channel. For TCP the stack owns the link endpoint and the
// ESP carrier, so closing it joins the inbound pump; nothing is left detached.
func (c *protectedRegisterChannel) Close() error {
	if c == nil {
		return nil
	}
	var firstErr error
	if c.conn != nil {
		if err := c.conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.tcpStack != nil {
		if err := c.tcpStack.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// The UDP secure channel is intentionally NOT closed here: on success it is
	// handed to the caller as state.secureConn and outlives the REGISTER.
	return firstErr
}

// protectedTCPActivation carries the runtime facts the activation gate needs.
//
// It is a value, not a package-level flag, because the gate must reflect what is
// actually listening right now for the CURRENT SA generation. A compile-time
// constant alone would keep reporting "ready" after a listener died, or after an
// SA replacement retired the generation the listener belonged to.
type protectedTCPActivation struct {
	// ServerFlowReady is true only when a protected server listener is accepting
	// on the stable port_us of the generation named below.
	ServerFlowReady bool
	// Generation identifies the SA generation the listener belongs to. Zero means
	// no generation is current, which can never be ready.
	Generation uint64
}

// ready reports whether this activation state permits a protected TCP send.
func (a protectedTCPActivation) ready() bool {
	return a.ServerFlowReady && a.Generation != 0
}

// resolveProtectedTransport decides INTENT; authorizeProtectedTCPActivation
// decides whether that intent may reach the wire. Splitting the two is the whole
// point of this gate.
//
// An explicit `transport=tcp` is a transport intent. It is NOT a licence to
// register without a server flow: TS 33.203 clause 7.1 requires the P-CSCF to
// open its own connection to port_us for every network-originated request, and
// TS 24.229 clause 3.1 NOTE 3 leaves it no alternative flow. A UE that dials
// port_uc without listening on port_us therefore registers successfully and then
// silently misses every terminating INVITE, MESSAGE and NOTIFY. That is a worse
// outcome than refusing to send, so explicit and auto-derived TCP are gated
// identically.
//
// Falling back to UDP is not a safe alternative either: the plan only says TCP
// because the request does not fit UDP, so a downgrade would send a request that
// fragments - the exact failure this whole path exists to remove. The gate
// therefore fails closed rather than downgrading.
func authorizeProtectedTCPActivation(plan protectedRegisterPlan, activation protectedTCPActivation) error {
	if plan.Transport == "" {
		return fmt.Errorf("imscore: protected transport plan is unresolved")
	}
	if _, err := resolveProtectedTransport(plan.Transport); err != nil {
		return err
	}
	if plan.Transport != protectedTransportTCP {
		return nil
	}
	if !protectedTCPClientProductionEnabled {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonServerFlowPending}
	}
	if !activation.ready() {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonServerFlowPending}
	}
	return nil
}

// protectedTCPUnavailableError is a bounded, classified refusal. It carries a
// closed-enum reason and nothing else - no address, port, SPI or SIP content.
type protectedTCPUnavailableError struct {
	reason string
}

func (e *protectedTCPUnavailableError) Error() string {
	return fmt.Sprintf("imscore: protected TCP is not available (reason=%s)", e.reason)
}

// Reason exposes the classification for diagnostics.
func (e *protectedTCPUnavailableError) Reason() string {
	if e == nil {
		return ""
	}
	return e.reason
}

// protectedDialPath names the branch a resolved transport dispatches to. It is a
// closed enum so the dispatch decision can be asserted and logged on its own,
// without opening a tunnel.
const (
	protectedDialPathUDP = "legacy_udp_secure_channel"
	protectedDialPathTCP = "protected_gvisor_tcp"
)

// protectedDialPathFor reports which branch a resolved transport takes.
//
// This exists so the dispatch itself is testable in isolation: the interesting
// property is that a third value can never land in the UDP branch, and that is
// far easier to prove over a pure function than over a dial that needs a tunnel.
func protectedDialPathFor(transport string) (string, error) {
	resolved, err := resolveProtectedTransport(transport)
	if err != nil {
		return "", err
	}
	switch resolved {
	case protectedTransportUDP:
		return protectedDialPathUDP, nil
	case protectedTransportTCP:
		return protectedDialPathTCP, nil
	default:
		return "", fmt.Errorf("imscore: unsupported protected transport %q", transport)
	}
}

// applyProtectedTransportProductionGate reports whether production may act on a
// decided plan, without altering it.
//
// It deliberately does NOT rewrite Transport. An earlier version downgraded a
// TCP plan to UDP here, which was wrong twice over: it let an explicit TCP
// configuration pass as a licence to register without a server flow, and for the
// auto-derived case it "resolved" the problem by sending the very request that
// does not fit UDP. The plan is now returned unchanged and the refusal is an
// error, so a caller cannot mistake a downgrade for success.
func applyProtectedTransportProductionGate(plan protectedRegisterPlan, activation protectedTCPActivation) (protectedRegisterPlan, error) {
	if err := authorizeProtectedTCPActivation(plan, activation); err != nil {
		return protectedRegisterPlan{}, err
	}
	return plan, nil
}

// dialProtectedRegisterConn is the name the register flow calls. It returns the
// channel's net.Conn plus the channel itself so the caller can tear down the
// whole protected stack, not just the connection.
func dialProtectedRegisterConn(
	ctx context.Context,
	cfg Config,
	swuTCP voiceclient.SWUTCPDialer,
	state registerState,
	transport string,
) (*protectedRegisterChannel, error) {
	return dialProtectedRegisterChannel(ctx, cfg, swuTCP, state, transport)
}

// dialProtectedRegisterChannel opens the protected channel for the transport the
// plan selected.
func dialProtectedRegisterChannel(
	ctx context.Context,
	cfg Config,
	swuTCP voiceclient.SWUTCPDialer,
	state registerState,
	transport string,
) (*protectedRegisterChannel, error) {
	resolved, err := resolveProtectedTransport(transport)
	if err != nil {
		return nil, err
	}
	switch resolved {
	case protectedTransportUDP:
		// The legacy path, unchanged. dialSecureRegisterConn still enforces its
		// own UDP assertion, so this branch cannot be reached with a TCP state.
		secure, err := dialSecureRegisterConn(ctx, cfg, swuTCP, state)
		if err != nil {
			return nil, err
		}
		return &protectedRegisterChannel{
			conn:      secure,
			secure:    secure,
			transport: protectedTransportUDP,
		}, nil
	case protectedTransportTCP:
		return dialProtectedTCPRegisterChannel(ctx, cfg, swuTCP, state)
	default:
		// Unreachable: resolveProtectedTransport already failed closed.
		return nil, fmt.Errorf("imscore: unsupported protected transport %q", transport)
	}
}

// dialProtectedTCPRegisterChannel builds the real protected TCP client flow.
//
// Every egress leaves through ipsec3gpp's protected link endpoint, which has no
// dataplane writer of its own, so no cleartext TCP segment can reach the SWu
// tunnel even if this function is wrong.
func dialProtectedTCPRegisterChannel(
	ctx context.Context,
	cfg Config,
	swuTCP voiceclient.SWUTCPDialer,
	state registerState,
) (*protectedRegisterChannel, error) {
	if swuTCP == nil {
		return nil, fmt.Errorf("imscore: protected TCP requires SWu raw IP dataplane")
	}
	rawDialer, ok := swuTCP.(voiceclient.SWURawIPDialer)
	if !ok {
		return nil, fmt.Errorf("imscore: SWu dialer does not expose raw IP")
	}
	if state.transport == nil {
		return nil, fmt.Errorf("imscore: protected TCP requires an installed ESP transform")
	}
	remoteIP := net.IP(state.ipsecPolicy.RemoteIP)
	if remoteIP == nil {
		return nil, fmt.Errorf("imscore: protected TCP has no P-CSCF address")
	}

	// The ESP carrier is the same raw IP connection the UDP path uses: protocol
	// 50 to the winning candidate, taken from the per-attempt policy.
	carrier, err := rawDialer.DialContextIP(ctx, cfg.LocalIP, remoteIP, 50)
	if err != nil {
		return nil, err
	}
	stack, err := ipsec3gpp.NewProtectedTCPStack(
		carrier, state.transport, state.ipsecPolicy, registerProtectedInnerMTU)
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}
	conn, err := stack.DialClientFlow(ctx)
	if err != nil {
		_ = stack.Close()
		return nil, err
	}
	return &protectedRegisterChannel{
		conn:      conn,
		tcpStack:  stack,
		transport: protectedTransportTCP,
	}, nil
}
