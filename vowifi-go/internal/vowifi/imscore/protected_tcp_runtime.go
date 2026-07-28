package imscore

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// protectedTCPRuntime owns everything that belongs to ONE SA generation's
// protected TCP path: one raw ESP carrier, one gvisor stack, one link endpoint,
// one inbound pump, and both SIP flows.
//
// Why this must be a single object rather than two per-flow ones:
//
// voiceclient.swuNetstack.dispatchRawIPPacket delivers a COPY of every inbound
// packet to each registered raw connection whose (src, dst, protocol) triple
// matches. Two carriers for the same triple therefore means every ESP packet is
// delivered twice. Sharing one Transport would make the second copy a replay
// rejection (a silent transform error); using two Transports would give two
// independent replay windows that each advance on the same packet. Both failures
// are invisible from the SIP layer, so the only safe structure is one carrier.
//
// The generation is supplied by the Service-owned allocator and only stamped
// here. A runtime never mints one: a runtime is created per registration attempt,
// and the generation's entire purpose is to distinguish a current SA from a
// retired one across attempts.
type protectedTCPRuntime struct {
	stack      *ipsec3gpp.ProtectedTCPStack
	listener   net.Listener
	generation uint64

	// policy and transform are the SA this runtime is bound to. They are kept so a
	// send can prove the runtime belongs to the state it is about to protect,
	// rather than trusting the caller to pair them correctly. A runtime built from
	// a different policy would encrypt with the wrong keys or bind the wrong port.
	policy    ipsec3gpp.Policy
	transform *ipsec3gpp.Transport

	// pumps and transforms are recorded rather than derived so the invariants
	// "exactly one inbound pump" and "exactly one replay window per SPI" can be
	// asserted directly instead of inferred from the absence of a second dial.
	pumps      int
	transforms int

	mu          sync.Mutex
	closed      bool
	joined      bool
	transferred bool

	// portRelease returns the rotating port_uc to the allocator on teardown. It is
	// held here because the runtime is the last thing to die, and the port must not
	// be reissued while this generation's SA may still be installed at the P-CSCF.
	portRelease     func()
	portReleaseOnce sync.Once

	closeOnce sync.Once
}

// startProtectedTCPRuntime dials the single ESP carrier, builds the stack, and
// brings the server listener up.
//
// Ordering is load-bearing and matches TS 33.203 clause 7.1: the listener on
// port_us must be accepting BEFORE the protected REGISTER goes out, because the
// P-CSCF may open its port_pc -> port_us connection as soon as it has answered.
// A runtime that cannot listen is therefore a failed runtime, not a degraded one:
// it returns an error and releases the carrier rather than handing back a
// client-only path that would pass the activation gate's generation check.
func startProtectedTCPRuntime(
	ctx context.Context,
	cfg Config,
	swuTCP voiceclient.SWUTCPDialer,
	state registerState,
) (*protectedTCPRuntime, error) {
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

	// The ONE dial. Everything below shares this carrier.
	carrier, err := rawDialer.DialContextIP(ctx, cfg.LocalIP, remoteIP, 50)
	if err != nil {
		return nil, err
	}

	protectedStack, err := ipsec3gpp.NewProtectedTCPStack(
		carrier, state.transport, state.ipsecPolicy, registerProtectedInnerMTU)
	if err != nil {
		_ = carrier.Close()
		return nil, err
	}

	// The listener comes up before the runtime is considered started, so a caller
	// can never observe a runtime whose terminating path is missing.
	listener, err := protectedStack.ListenServerFlow()
	if err != nil {
		// Closing the stack also closes the carrier and joins the pump.
		_ = protectedStack.Close()
		return nil, err
	}

	return &protectedTCPRuntime{
		stack:      protectedStack,
		listener:   listener,
		generation: state.generation,
		policy:     state.ipsecPolicy,
		transform:  state.transport,
		pumps:      1,
		transforms: 1,
	}, nil
}

// Generation is the SA generation this runtime belongs to.
func (r *protectedTCPRuntime) Generation() uint64 {
	if r == nil {
		return 0
	}
	return r.generation
}

// ProtectedServerPort is the stable port_us this runtime listens on.
func (r *protectedTCPRuntime) ProtectedServerPort() int {
	if r == nil {
		return 0
	}
	return r.policy.FlowS.LocalPort
}

// ProtectedClientPort is the rotating port_uc this runtime's client flow binds.
func (r *protectedTCPRuntime) ProtectedClientPort() int {
	if r == nil {
		return 0
	}
	return r.policy.FlowC.LocalPort
}

// InboundPumpCount is the number of ESP read loops this runtime owns. It must be
// exactly one: a second pump on the same carrier would race for packets.
func (r *protectedTCPRuntime) InboundPumpCount() int {
	if r == nil {
		return 0
	}
	return r.pumps
}

// TransformCount is the number of ESP transforms, and therefore the number of
// replay-window sets, this runtime owns.
func (r *protectedTCPRuntime) TransformCount() int {
	if r == nil {
		return 0
	}
	return r.transforms
}

// LegacySecureChannel always returns nil. It exists so a test can assert the
// absence structurally rather than by grepping, since creating one would register
// a second raw connection for this triple and duplicate every inbound packet.
func (r *protectedTCPRuntime) LegacySecureChannel() *ipsec3gpp.SecureChannelConn {
	return nil
}

// RegisterChannel is the channel the register flow sends on. Its secure field is
// nil by construction: the TCP path has no packet-mode channel.
func (r *protectedTCPRuntime) RegisterChannel() *protectedRegisterChannel {
	if r == nil {
		return nil
	}
	return &protectedRegisterChannel{
		tcpStack:  r.stack,
		transport: protectedTransportTCP,
	}
}

// ServerFlowReady reports whether the terminating listener is accepting for this
// generation right now.
func (r *protectedTCPRuntime) ServerFlowReady() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closed && r.listener != nil
}

// Activation is what the transport gate reads. It is derived from live state, not
// from a compile-time constant, so a dead listener or a retired generation can
// never look ready.
func (r *protectedTCPRuntime) Activation() protectedTCPActivation {
	if r == nil {
		return protectedTCPActivation{}
	}
	if !r.ServerFlowReady() {
		return protectedTCPActivation{}
	}
	return protectedTCPActivation{
		ServerFlowReady: true,
		Generation:      r.generation,
	}
}

// Snapshot exposes the link endpoint counters for diagnostics.
func (r *protectedTCPRuntime) Snapshot() ipsec3gpp.ProtectedLinkSnapshot {
	if r == nil {
		return ipsec3gpp.ProtectedLinkSnapshot{}
	}
	return r.stack.Snapshot()
}

// ClientFlowRetransmissions is how many segments gvisor's sender resent on the
// protected client flow.
//
// It comes from the TCP endpoint rather than the link endpoint: from the link's
// point of view a retransmitted segment is indistinguishable from a new one
// without inspecting sequence numbers, which this code deliberately does not
// retain.
func (r *protectedTCPRuntime) ClientFlowRetransmissions() int {
	if r == nil || r.stack == nil {
		return 0
	}
	return r.stack.ClientFlowRetransmissions()
}

// SafeMSS is the MSS derived from the negotiated transform.
func (r *protectedTCPRuntime) SafeMSS() int {
	if r == nil {
		return 0
	}
	return r.stack.SafeMSS()
}

// DialClientFlow opens the UE-originating connection on the shared carrier.
func (r *protectedTCPRuntime) DialClientFlow(ctx context.Context) (net.Conn, error) {
	if r == nil {
		return nil, fmt.Errorf("imscore: protected TCP runtime is nil")
	}
	r.mu.Lock()
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("imscore: protected TCP runtime is closed")
	}
	return r.stack.DialClientFlow(ctx)
}

// AcceptServerFlow accepts one P-CSCF-originated connection.
func (r *protectedTCPRuntime) AcceptServerFlow() (net.Conn, error) {
	if r == nil {
		return nil, fmt.Errorf("imscore: protected TCP runtime is nil")
	}
	r.mu.Lock()
	listener := r.listener
	closed := r.closed
	r.mu.Unlock()
	if closed || listener == nil {
		return nil, net.ErrClosed
	}
	return listener.Accept()
}

// BindPortRelease registers the allocator callback that frees this generation's
// rotating port_uc when the runtime dies.
//
// The release is deliberately tied to runtime teardown rather than to the end of
// the REGISTER transaction: the SA stays installed for as long as the runtime
// lives, and reissuing port_uc while that SA exists would put two SAs on one
// (LocalPort, RemotePort) pair.
func (r *protectedTCPRuntime) BindPortRelease(allocator *protectedPortAllocator, generation uint64) {
	if r == nil || allocator == nil {
		return
	}
	r.mu.Lock()
	r.portRelease = func() { allocator.release(generation) }
	r.mu.Unlock()
}

// TakeOwnership transfers responsibility for this runtime's lifetime to a new
// owner, exactly once.
//
// The register flow closes the runtime on every failure path via
// CloseUnlessTransferred. On success it hands the runtime to the Service instead,
// and the transfer must be single: two owners would each call Close, and the
// second would run against a torn-down stack.
func (r *protectedTCPRuntime) TakeOwnership() (*protectedTCPRuntime, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.transferred || r.closed {
		return nil, false
	}
	r.transferred = true
	return r, true
}

// CloseUnlessTransferred is the register flow's cleanup. It is a no-op once
// ownership has moved, so a deferred cleanup cannot tear down a runtime the
// Service is now using.
func (r *protectedTCPRuntime) CloseUnlessTransferred() {
	if r == nil {
		return
	}
	r.mu.Lock()
	transferred := r.transferred
	r.mu.Unlock()
	if transferred {
		return
	}
	r.Close()
}

// Closed reports whether teardown has run.
func (r *protectedTCPRuntime) Closed() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// Joined reports whether Close waited for the inbound pump to exit. It is the
// difference between signalling teardown and completing it: an unjoined pump can
// still deliver a packet into a stack that is being replaced.
func (r *protectedTCPRuntime) Joined() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.joined
}

// Close tears down the listener, the stack, the endpoint, the pump and the
// carrier, then releases the rotating client port.
//
// It is idempotent and safe under concurrent callers: the register flow closes on
// error paths, a deferred cleanup may follow, and an SA replacement closes the
// retired runtime from another goroutine.
func (r *protectedTCPRuntime) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		listener := r.listener
		r.listener = nil
		release := r.portRelease
		r.mu.Unlock()

		if listener != nil {
			_ = listener.Close()
		}
		// Closing the stack closes the link endpoint and the carrier, and waits for
		// the inbound pump.
		if r.stack != nil {
			_ = r.stack.Close()
		}

		r.mu.Lock()
		r.joined = true
		r.mu.Unlock()

		if release != nil {
			r.portReleaseOnce.Do(release)
		}
	})
}
