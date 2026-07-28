package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Phase A/B tests for the PRODUCTION protected link endpoint.
//
// The endpoint is the fail-closed boundary between a real gvisor TCP stack and
// the IMS ESP transform. Its whole reason to exist is that every one of these
// properties is structural rather than a matter of discipline at the call site:
//
//   - the only egress is TransformOutbound, and the endpoint holds no raw or
//     dataplane writer it could bypass ESP with;
//   - the only ingress is TransformInbound, and the ESP check runs BEFORE it,
//     because TransformInbound passes non-ESP packets through unchanged;
//   - the MSS clamp runs only on packets that already passed ESP integrity and
//     replay, on a local plaintext copy, and never on the wire packet;
//   - anything unmodelled - unknown transform, oversize packet, foreign
//     selector, malformed MSS - fails closed instead of degrading quietly.
//
// Everything asserted is a length, count, flag or enum bucket. No SIP text,
// key, IV, ciphertext, address, port value, SPI or identity is printed.

// ---------------------------------------------------------------------------
// A carrier that records what the endpoint writes and lets a test feed inbound
// packets. It is deliberately NOT a raw dataplane: the endpoint cannot reach
// past it.
// ---------------------------------------------------------------------------

type plinkCarrier struct {
	mu       sync.Mutex
	writes   [][]byte
	inbound  chan []byte
	closed   chan struct{}
	once     sync.Once
	writeErr error
}

func newPlinkCarrier() *plinkCarrier {
	return &plinkCarrier{
		inbound: make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
}

func (c *plinkCarrier) Read(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case pkt, ok := <-c.inbound:
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(p, pkt), nil
	}
}

func (c *plinkCarrier) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *plinkCarrier) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (*plinkCarrier) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (*plinkCarrier) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (*plinkCarrier) SetDeadline(time.Time) error      { return nil }
func (*plinkCarrier) SetReadDeadline(time.Time) error  { return nil }
func (*plinkCarrier) SetWriteDeadline(time.Time) error { return nil }

func (c *plinkCarrier) captured() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

var _ net.Conn = (*plinkCarrier)(nil)

// plinkDispatcher records what the endpoint delivered into the stack.
type plinkDispatcher struct {
	mu        sync.Mutex
	delivered [][]byte
}

func (d *plinkDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.delivered = append(d.delivered, protectedLinkPacketBytes(pkt))
}

func (*plinkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (d *plinkDispatcher) all() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.delivered))
	copy(out, d.delivered)
	return out
}

var _ stack.NetworkDispatcher = (*plinkDispatcher)(nil)

// ---------------------------------------------------------------------------
// Synthetic handshake segments. Built by hand so the tests do not depend on the
// code under test to produce their inputs.
// ---------------------------------------------------------------------------

// plinkSegment builds an IPv6+TCP packet from src->dst with the given flags and
// options. Ports are taken from the policy so the selector matches.
func plinkSegment(src, dst []byte, srcPort, dstPort int, flags byte, options, payload []byte) []byte {
	for len(options)%4 != 0 {
		options = append(options, 0)
	}
	segLen := header.TCPMinimumSize + len(options) + len(payload)
	pkt := make([]byte, protectedIPv6HeaderLen+segLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(segLen))
	pkt[6] = ipProtoTCP
	pkt[7] = 64
	copy(pkt[8:24], src)
	copy(pkt[24:40], dst)

	seg := pkt[protectedIPv6HeaderLen:]
	binary.BigEndian.PutUint16(seg[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(seg[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(seg[4:8], 0x11223344)
	binary.BigEndian.PutUint32(seg[8:12], 0x55667788)
	seg[12] = byte((header.TCPMinimumSize+len(options))/4) << 4
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 0xffff)
	copy(seg[header.TCPMinimumSize:], options)
	copy(seg[header.TCPMinimumSize+len(options):], payload)
	if err := rewriteTCPChecksum(pkt); err != nil {
		panic(err)
	}
	return pkt
}

func plinkMSSOption(mss int) []byte {
	return []byte{2, 4, byte(mss >> 8), byte(mss)}
}

// plinkEndpoint wires an endpoint to a carrier and a recording dispatcher.
func plinkEndpoint(t *testing.T) (*ProtectedLinkEndpoint, *plinkCarrier, *plinkDispatcher, Policy) {
	t.Helper()
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	carrier := newPlinkCarrier()
	ep, err := NewProtectedLinkEndpoint(carrier, transport, policy, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("NewProtectedLinkEndpoint: %v", err)
	}
	dispatcher := &plinkDispatcher{}
	ep.Attach(dispatcher)
	t.Cleanup(func() {
		ep.Close()
		carrier.Close()
		ep.Wait()
	})
	return ep, carrier, dispatcher, policy
}

// peerTransport builds the far-side transform so tests can produce genuine ESP.
func peerTransport(t *testing.T, policy Policy) *Transport {
	t.Helper()
	reversed := reverseProtoTCPPolicy(policy)
	transport, err := NewTransport(reversed)
	if err != nil {
		t.Fatalf("peer NewTransport: %v", err)
	}
	return transport
}

// ---------------------------------------------------------------------------
// TestProtectedTCPClientAndServerFlowsAdvertiseSafeMSS
// ---------------------------------------------------------------------------

// Both directions must derive the SAME safe MSS from the SAME negotiated
// transform: the client flow advertises it in its SYN, the server flow in its
// SYN-ACK. A per-direction value would let one side overrun the ESP budget.
func TestProtectedTCPClientAndServerFlowsAdvertiseSafeMSS(t *testing.T) {
	policy := oraclePolicy(t)

	plan, err := PlanProtectedMSS(policy, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("PlanProtectedMSS: %v", err)
	}
	if plan.SafeMSS != 1178 {
		t.Fatalf("safe MSS = %d, want 1178 for AES-CBC/HMAC-SHA-1-96 at MTU %d",
			plan.SafeMSS, ProtectedTunnelMTU)
	}
	if plan.MaxSegmentLen != 1198 {
		t.Fatalf("max segment = %d, want 1198", plan.MaxSegmentLen)
	}

	// Both flows must agree, since both are protected by the same transform.
	clientMSS, err := DeriveSafeMSS(policy.FlowC, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("client DeriveSafeMSS: %v", err)
	}
	serverMSS, err := DeriveSafeMSS(policy.FlowS, ProtectedTunnelMTU)
	if err != nil {
		t.Fatalf("server DeriveSafeMSS: %v", err)
	}
	if clientMSS != plan.SafeMSS || serverMSS != plan.SafeMSS {
		t.Fatalf("flow MSS disagree: client=%d server=%d plan=%d", clientMSS, serverMSS, plan.SafeMSS)
	}

	// The endpoint keeps the transform-derived value as its hard upper bound,
	// then applies the conservative path-compatibility ceiling.
	ep, _, _, _ := plinkEndpoint(t)
	wantEndpointMSS := plan.SafeMSS
	if wantEndpointMSS > protectedTCPConservativeMSSCap {
		wantEndpointMSS = protectedTCPConservativeMSSCap
	}
	if ep.SafeMSS() != wantEndpointMSS {
		t.Fatalf("endpoint SafeMSS = %d, want %d", ep.SafeMSS(), wantEndpointMSS)
	}
	if ep.MTU() != uint32(ProtectedTunnelMTU) {
		t.Fatalf("endpoint MTU = %d, want %d", ep.MTU(), ProtectedTunnelMTU)
	}
	if ep.MTU() < header.IPv6MinimumMTU {
		t.Fatalf("endpoint MTU %d is below the IPv6 minimum", ep.MTU())
	}
	// GSO/TSO must not be advertised, or gvisor may hand over a super-packet.
	if caps := ep.Capabilities(); caps != stack.CapabilityNone {
		t.Fatalf("endpoint capabilities = %#x, want none", caps)
	}

	// The full segment must stay in budget for every option length, because
	// options shrink the payload while the segment stays at the budget.
	for _, optLen := range []int{0, 12, 20, 40} {
		payload := plan.SafeMSS - optLen
		segLen := header.TCPMinimumSize + optLen + payload
		if segLen != plan.MaxSegmentLen {
			t.Fatalf("segment with %d option bytes = %d, want the constant budget %d",
				optLen, segLen, plan.MaxSegmentLen)
		}
		inner, err := PredictProtectedESPLen(policy.FlowC, protectedIPv6HeaderLen+segLen)
		if err != nil {
			t.Fatalf("PredictProtectedESPLen: %v", err)
		}
		if inner > ProtectedTunnelMTU {
			t.Fatalf("inner packet with %d option bytes = %d, want <= %d",
				optLen, inner, ProtectedTunnelMTU)
		}
	}
	t.Logf("MEASURED safe_mss=%d max_segment=%d link_mtu=%d capabilities=0 flows_agree=true",
		plan.SafeMSS, plan.MaxSegmentLen, ProtectedTunnelMTU)
}

// ---------------------------------------------------------------------------
// TestProtectedTCPMSSClampAppliesOnlyAfterESPVerification
// ---------------------------------------------------------------------------

// The clamp must be unreachable for a packet that has not passed ESP integrity.
// This is the property that stops an off-path packet from steering our send
// budget: a forged or cleartext SYN-ACK is dropped, never clamped, never
// delivered.
func TestProtectedTCPMSSClampAppliesOnlyAfterESPVerification(t *testing.T) {
	ep, _, dispatcher, policy := plinkEndpoint(t)
	peer := peerTransport(t, policy)

	oversizeMSS := ep.SafeMSS() + 400
	synAck := plinkSegment(
		policy.RemoteIP, policy.LocalIP,
		policy.FlowC.RemotePort, policy.FlowC.LocalPort,
		tcpFlagSYN|tcpFlagACK, plinkMSSOption(oversizeMSS), nil)

	// 1. Cleartext: not ESP at all. Must be rejected before the transform.
	ep.deliverInbound(synAck)
	if got := ep.Snapshot(); got.InboundRejected != 1 || got.HandshakeClamped != 0 || got.InboundAccepted != 0 {
		t.Fatalf("cleartext SYN-ACK: rejected=%d clamped=%d accepted=%d, want 1/0/0",
			got.InboundRejected, got.HandshakeClamped, got.InboundAccepted)
	}
	if len(dispatcher.all()) != 0 {
		t.Fatal("a cleartext packet was delivered into the stack")
	}

	// 2. ESP-shaped but corrupted: integrity must fail, so the clamp must not run.
	genuine, err := peer.TransformOutbound(synAck)
	if err != nil {
		t.Fatalf("peer TransformOutbound: %v", err)
	}
	corrupted := append([]byte(nil), genuine...)
	corrupted[len(corrupted)-1] ^= 0xff // break the ICV
	before := ep.Snapshot()
	ep.deliverInbound(corrupted)
	after := ep.Snapshot()
	if after.InboundRejected != before.InboundRejected+1 {
		t.Fatal("a corrupted ESP packet was not rejected")
	}
	if after.HandshakeClamped != before.HandshakeClamped {
		t.Fatal("the MSS clamp ran on a packet that failed ESP integrity")
	}
	if after.InboundAccepted != before.InboundAccepted {
		t.Fatal("a corrupted ESP packet was delivered into the stack")
	}

	// 3. Genuine ESP: now the clamp is allowed to run.
	ep.deliverInbound(genuine)
	final := ep.Snapshot()
	if final.HandshakeClamped != 1 {
		t.Fatalf("handshake_clamped = %d, want 1 after a verified SYN-ACK", final.HandshakeClamped)
	}
	if final.InboundAccepted != 1 {
		t.Fatalf("inbound_accepted = %d, want 1", final.InboundAccepted)
	}
	delivered := dispatcher.all()
	if len(delivered) != 1 {
		t.Fatalf("delivered %d packets, want 1", len(delivered))
	}
	if got := plinkReadMSS(t, delivered[0]); got != ep.SafeMSS() {
		t.Fatalf("delivered MSS = %d, want the clamped %d", got, ep.SafeMSS())
	}
	t.Logf("MEASURED cleartext_clamped=false corrupt_clamped=false verified_clamped=true effective_mss=%d",
		ep.SafeMSS())
}

// plinkReadMSS extracts the MSS option value from an IPv6+TCP packet.
func plinkReadMSS(t *testing.T, packet []byte) int {
	t.Helper()
	if len(packet) < protectedIPv6HeaderLen+header.TCPMinimumSize {
		t.Fatal("packet too short for a TCP segment")
	}
	seg := packet[protectedIPv6HeaderLen:]
	headerLen := int(seg[12]>>4) * 4
	if headerLen < header.TCPMinimumSize || headerLen > len(seg) {
		t.Fatal("invalid TCP data offset")
	}
	options := seg[header.TCPMinimumSize:headerLen]
	for i := 0; i < len(options); {
		switch options[i] {
		case 0:
			return 0
		case 1:
			i++
		default:
			if i+1 >= len(options) {
				return 0
			}
			optLen := int(options[i+1])
			if optLen < 2 || i+optLen > len(options) {
				return 0
			}
			if options[i] == 2 && optLen == 4 {
				return int(binary.BigEndian.Uint16(options[i+2 : i+4]))
			}
			i += optLen
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// TestProtectedTCPInboundSYNAndSYNACKClampAreLocal
// ---------------------------------------------------------------------------

// Both handshake directions get clamped - an inbound SYN (P-CSCF opening the
// server flow to port_us) and an inbound SYN-ACK (our client flow being
// answered) - and in both cases the wire packet is untouched and nothing is
// written back.
func TestProtectedTCPInboundSYNAndSYNACKClampAreLocal(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     byte
		srcPort   int
		dstPort   int
		peerMSS   int
		wantMSS   func(safe int) int
		wantClamp bool
	}{
		{
			name:  "server_flow_inbound_SYN_oversize",
			flags: tcpFlagSYN, peerMSS: 1440,
			wantMSS:   func(safe int) int { return safe },
			wantClamp: true,
		},
		{
			name:  "client_flow_inbound_SYNACK_oversize",
			flags: tcpFlagSYN | tcpFlagACK, peerMSS: 65535,
			wantMSS:   func(safe int) int { return safe },
			wantClamp: true,
		},
		{
			name:  "inbound_SYNACK_already_small",
			flags: tcpFlagSYN | tcpFlagACK, peerMSS: 900,
			wantMSS:   func(int) int { return 900 },
			wantClamp: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, carrier, dispatcher, policy := plinkEndpoint(t)
			peer := peerTransport(t, policy)

			// An inbound SYN for the server flow arrives on the FlowS port pair;
			// an inbound SYN-ACK for the client flow on the FlowC pair.
			srcPort, dstPort := policy.FlowC.RemotePort, policy.FlowC.LocalPort
			if tc.flags == tcpFlagSYN {
				srcPort, dstPort = policy.FlowS.RemotePort, policy.FlowS.LocalPort
			}
			plain := plinkSegment(policy.RemoteIP, policy.LocalIP, srcPort, dstPort,
				tc.flags, plinkMSSOption(tc.peerMSS), nil)
			esp, err := peer.TransformOutbound(plain)
			if err != nil {
				t.Fatalf("peer TransformOutbound: %v", err)
			}
			wireBefore := append([]byte(nil), esp...)

			ep.deliverInbound(esp)

			// The verified wire packet must be byte-identical afterwards.
			if !bytes.Equal(esp, wireBefore) {
				t.Fatal("the verified wire packet was modified in place")
			}
			// Nothing may be written back to the carrier by an inbound packet.
			if n := len(carrier.captured()); n != 0 {
				t.Fatalf("%d packets were written to the carrier while handling an inbound packet", n)
			}

			delivered := dispatcher.all()
			if len(delivered) != 1 {
				t.Fatalf("delivered %d packets, want 1", len(delivered))
			}
			gotMSS := plinkReadMSS(t, delivered[0])
			if want := tc.wantMSS(ep.SafeMSS()); gotMSS != want {
				t.Fatalf("delivered MSS = %d, want %d", gotMSS, want)
			}
			snap := ep.Snapshot()
			if tc.wantClamp && snap.HandshakeClamped != 1 {
				t.Fatalf("handshake_clamped = %d, want 1", snap.HandshakeClamped)
			}
			if !tc.wantClamp && snap.HandshakeClamped != 0 {
				t.Fatalf("handshake_clamped = %d, want 0 for an already-small MSS", snap.HandshakeClamped)
			}
			if snap.HandshakeFailClosed != 0 {
				t.Fatalf("handshake_fail_closed = %d, want 0", snap.HandshakeFailClosed)
			}

			// The rest of the segment must be untouched: only MSS + checksum change.
			origSeg := plain[protectedIPv6HeaderLen:]
			gotSeg := delivered[0][protectedIPv6HeaderLen:]
			if len(origSeg) != len(gotSeg) {
				t.Fatalf("segment length changed: %d -> %d", len(origSeg), len(gotSeg))
			}
			if !bytes.Equal(origSeg[0:16], gotSeg[0:16]) {
				t.Fatal("ports, sequence, ack, data offset, flags or window changed")
			}
			t.Logf("MEASURED clamp_applied=%v effective_mss=%d wire_rewrite_count=0 carrier_writes=0",
				snap.HandshakeClamped == 1, gotMSS)
		})
	}
}

// ---------------------------------------------------------------------------
// TestProtectedTCPMalformedOrMissingMSSFailsBeforeSIP
// ---------------------------------------------------------------------------

// A handshake segment whose MSS option cannot be trusted must fail closed: the
// packet is dropped, nothing is delivered into the stack, so the connection
// never completes and no SIP is ever sent on it. The endpoint must not invent
// an MSS option.
func TestProtectedTCPMalformedOrMissingMSSFailsBeforeSIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{name: "missing_mss", options: nil},
		{name: "mss_wrong_length", options: []byte{2, 3, 0x04, 0x00}},
		{name: "duplicate_mss", options: append(plinkMSSOption(1400), plinkMSSOption(1200)...)},
		{name: "zero_mss", options: plinkMSSOption(0)},
		{name: "truncated_option", options: []byte{2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep, carrier, dispatcher, policy := plinkEndpoint(t)
			peer := peerTransport(t, policy)

			plain := plinkSegment(policy.RemoteIP, policy.LocalIP,
				policy.FlowC.RemotePort, policy.FlowC.LocalPort,
				tcpFlagSYN|tcpFlagACK, tc.options, nil)
			esp, err := peer.TransformOutbound(plain)
			if err != nil {
				t.Fatalf("peer TransformOutbound: %v", err)
			}
			ep.deliverInbound(esp)

			snap := ep.Snapshot()
			if snap.HandshakeFailClosed != 1 {
				t.Fatalf("handshake_fail_closed = %d, want 1", snap.HandshakeFailClosed)
			}
			if snap.InboundAccepted != 0 {
				t.Fatalf("inbound_accepted = %d, want 0: the segment must not reach the stack",
					snap.InboundAccepted)
			}
			if snap.HandshakeClamped != 0 {
				t.Fatalf("handshake_clamped = %d, want 0", snap.HandshakeClamped)
			}
			if n := len(dispatcher.all()); n != 0 {
				t.Fatalf("%d packets were delivered despite an untrustworthy MSS", n)
			}
			if n := len(carrier.captured()); n != 0 {
				t.Fatalf("%d packets were written; nothing may be sent on a failed handshake", n)
			}

			// The classification must be a closed enum, never a guessed value.
			_, result, err := ClampHandshakeMSS(plain, ep.SafeMSS())
			if err == nil {
				t.Fatal("ClampHandshakeMSS accepted an untrustworthy MSS option")
			}
			if result.EffectiveMSS != 0 || result.Applied {
				t.Fatal("a failed clamp reported an effective MSS")
			}
			t.Logf("MEASURED original_mss_bucket=malformed_or_missing fail_closed=true delivered=0 sip_sent=false")
		})
	}
}

// A SYN that is not addressed to one of the negotiated protected port pairs
// must be dropped by the selector even when its ESP is valid.
func TestProtectedTCPForeignSelectorIsDropped(t *testing.T) {
	ep, _, dispatcher, policy := plinkEndpoint(t)

	// The peer must produce GENUINE ESP carrying foreign ports, so the drop is
	// attributable to the selector and not to the packet failing to be ESP at
	// all. Transport.TransformOutbound passes a packet through UNCHANGED when it
	// does not match the sender's own outbound selector, so handing the reversed
	// policy a foreign-port segment would emit cleartext and the endpoint would
	// reject it one step earlier, for the wrong reason.
	//
	// Instead the peer is given a policy whose own ports are the foreign ones
	// while its SPIs and keys stay those of the installed SA. The result is a
	// packet our transform accepts cryptographically and the selector must then
	// refuse.
	foreign := reverseProtoTCPPolicy(policy)
	foreign.FlowC.LocalPort = policy.FlowC.RemotePort + 9
	foreign.FlowC.RemotePort = policy.FlowC.LocalPort + 9
	peer, err := NewTransport(foreign)
	if err != nil {
		t.Fatalf("foreign-port peer NewTransport: %v", err)
	}

	plain := plinkSegment(policy.RemoteIP, policy.LocalIP,
		policy.FlowC.RemotePort+9, policy.FlowC.LocalPort+9,
		tcpFlagSYN|tcpFlagACK, plinkMSSOption(1440), nil)
	esp, err := peer.TransformOutbound(plain)
	if err != nil {
		t.Fatalf("peer TransformOutbound: %v", err)
	}
	// Precondition: the drop under test must be the selector's, so what arrives
	// has to be real ESP.
	if !isESPIPPacket(esp) {
		t.Fatal("the foreign-port packet was not protected; this test would prove nothing")
	}
	ep.deliverInbound(esp)

	snap := ep.Snapshot()
	if snap.InboundSelectorDrop != 1 {
		t.Fatalf("inbound_selector_drop = %d, want 1", snap.InboundSelectorDrop)
	}
	if snap.InboundAccepted != 0 || snap.HandshakeClamped != 0 {
		t.Fatal("a foreign selector packet was accepted or clamped")
	}
	if n := len(dispatcher.all()); n != 0 {
		t.Fatalf("%d foreign-selector packets were delivered", n)
	}
	t.Logf("MEASURED selector_drop=1 accepted=0 clamped=0")
}

// ---------------------------------------------------------------------------
// TestProtectedTCPUnknownTransformFailsClosed
// ---------------------------------------------------------------------------

// An unmodelled transform must prevent the endpoint from being created at all.
// Guessing AES-CBC overhead for an unknown cipher would silently reintroduce
// fragmentation, which is exactly the failure this whole path exists to remove.
func TestProtectedTCPUnknownTransformFailsClosed(t *testing.T) {
	base := oraclePolicy(t)

	for _, tc := range []struct {
		name string
		enc  string
		auth string
	}{
		{name: "unknown_enc", enc: "aes-gcm-16", auth: "hmac-sha-1-96"},
		{name: "unknown_auth", enc: "aes-cbc", auth: "hmac-sha-256-128"},
		{name: "empty_both", enc: "", auth: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := base
			policy.FlowC.EncAlg, policy.FlowC.AuthAlg = tc.enc, tc.auth
			policy.FlowS.EncAlg, policy.FlowS.AuthAlg = tc.enc, tc.auth

			if _, err := DeriveSafeMSS(policy.FlowC, ProtectedTunnelMTU); err == nil {
				t.Fatal("DeriveSafeMSS succeeded for an unmodelled transform")
			}
			if _, err := PlanProtectedMSS(policy, ProtectedTunnelMTU); err == nil {
				t.Fatal("PlanProtectedMSS succeeded for an unmodelled transform")
			}
			if _, err := PredictProtectedESPLen(policy.FlowC, 1000); err == nil {
				t.Fatal("PredictProtectedESPLen succeeded for an unmodelled transform")
			}

			// The endpoint constructor must refuse rather than default.
			transport, err := NewTransport(base)
			if err != nil {
				t.Fatalf("NewTransport: %v", err)
			}
			carrier := newPlinkCarrier()
			defer carrier.Close()
			if _, err := NewProtectedLinkEndpoint(carrier, transport, policy, ProtectedTunnelMTU); err == nil {
				t.Fatal("NewProtectedLinkEndpoint accepted an unmodelled transform")
			}
		})
	}

	// A sub-IPv6-minimum MTU must also be refused: gvisor's ipv6 endpoint folds
	// such a link MTU to zero, which collapses the send budget to one byte.
	transport, err := NewTransport(base)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	carrier := newPlinkCarrier()
	defer carrier.Close()
	for _, mtu := range []int{0, 576, header.IPv6MinimumMTU - 1} {
		if _, err := NewProtectedLinkEndpoint(carrier, transport, base, mtu); err == nil {
			t.Fatalf("NewProtectedLinkEndpoint accepted an illegal inner MTU %d", mtu)
		}
	}
	// And a nil carrier or transform must be refused, so no endpoint can exist
	// without an ESP path.
	if _, err := NewProtectedLinkEndpoint(nil, transport, base, ProtectedTunnelMTU); err == nil {
		t.Fatal("NewProtectedLinkEndpoint accepted a nil carrier")
	}
	if _, err := NewProtectedLinkEndpoint(carrier, nil, base, ProtectedTunnelMTU); err == nil {
		t.Fatal("NewProtectedLinkEndpoint accepted a nil transform")
	}
	t.Logf("MEASURED unknown_transform_fails_closed=true illegal_mtu_fails_closed=true nil_path_fails_closed=true")
}

// ---------------------------------------------------------------------------
// Egress: the only way out is TransformOutbound, and oversize fails closed.
// ---------------------------------------------------------------------------

// Every packet the stack hands over must leave as ESP, in budget, without a
// fragment header - or not leave at all.
func TestProtectedLinkEgressIsProtectedAndInBudget(t *testing.T) {
	ep, carrier, _, policy := plinkEndpoint(t)

	// An in-budget segment must be protected and written.
	payload := bytes.Repeat([]byte{'R'}, ep.SafeMSS()-12)
	inBudget := plinkSegment(policy.LocalIP, policy.RemoteIP,
		policy.FlowC.LocalPort, policy.FlowC.RemotePort,
		tcpFlagACK, plinkMSSOption(ep.SafeMSS()), payload)

	if err := plinkWrite(ep, inBudget); err != nil {
		t.Fatalf("in-budget write: %v", err)
	}
	written := carrier.captured()
	if len(written) != 1 {
		t.Fatalf("carrier received %d packets, want 1", len(written))
	}
	if !isESPIPPacket(written[0]) {
		t.Fatal("an unprotected packet reached the carrier")
	}
	if len(written[0]) > ProtectedTunnelMTU {
		t.Fatalf("protected packet is %d bytes, want <= %d", len(written[0]), ProtectedTunnelMTU)
	}
	// No IPv6 fragment header may ever appear on this path.
	if written[0][6] == 44 {
		t.Fatal("an IPv6 Fragment Header reached the carrier")
	}
	// The independent oracle must be able to verify it.
	encKey, authKey := oracleExpectedKeys(policy.FlowC)
	decoded := oracleDecodeESP(t, written[0][protectedIPv6HeaderLen:], encKey, authKey)
	if !decoded.icvValid {
		t.Fatal("the emitted ESP packet failed independent ICV verification")
	}

	// An over-budget segment must be held back, not fragmented and not sent.
	oversize := plinkSegment(policy.LocalIP, policy.RemoteIP,
		policy.FlowC.LocalPort, policy.FlowC.RemotePort,
		tcpFlagACK, nil, bytes.Repeat([]byte{'X'}, 4000))
	_ = plinkWrite(ep, oversize)
	if n := len(carrier.captured()); n != 1 {
		t.Fatalf("carrier received %d packets, want still 1: the oversize packet must be held", n)
	}
	snap := ep.Snapshot()
	if snap.OutboundOverBudget != 1 {
		t.Fatalf("outbound_over_budget = %d, want 1", snap.OutboundOverBudget)
	}
	if snap.OutboundProtected != 1 {
		t.Fatalf("outbound_protected = %d, want 1", snap.OutboundProtected)
	}
	if snap.OutboundUnprotected != 0 {
		t.Fatalf("outbound_unprotected = %d, want 0", snap.OutboundUnprotected)
	}

	// A packet that does not match the outbound selector must NOT be forwarded
	// as cleartext: TransformOutbound passes it through, and the endpoint must
	// drop it instead of writing it.
	foreign := plinkSegment(policy.LocalIP, policy.RemoteIP,
		policy.FlowC.LocalPort+7, policy.FlowC.RemotePort+7,
		tcpFlagACK, nil, []byte("x"))
	_ = plinkWrite(ep, foreign)
	if n := len(carrier.captured()); n != 1 {
		t.Fatalf("carrier received %d packets: a selector-mismatched packet was forwarded", n)
	}
	if got := ep.Snapshot().OutboundUnprotected; got != 1 {
		t.Fatalf("outbound_unprotected = %d, want 1", got)
	}
	t.Logf("MEASURED protected=1 over_budget_held=1 unprotected_dropped=1 fragments=0 max_esp_len=%d",
		len(written[0]))
}

// plinkWrite hands one cleartext IP packet to the endpoint the way gvisor would.
func plinkWrite(ep *ProtectedLinkEndpoint, packet []byte) error {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
	})
	var list stack.PacketBufferList
	list.PushBack(pkt)
	defer list.DecRef()
	if _, err := ep.WritePackets(list); err != nil {
		return errors.New(err.String())
	}
	return nil
}
