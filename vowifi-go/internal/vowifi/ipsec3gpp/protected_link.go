package ipsec3gpp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// ProtectedLinkEndpoint is a gvisor link endpoint whose only egress is the IMS
// ESP transform.
//
// It exists so that a REAL TCP stack can drive protected SIP: gvisor owns the
// handshake, sequence numbers, checksums, retransmission, windows, congestion
// control and segmentation, and this endpoint only PROTECTS the segments it
// produces. Nothing here synthesises a TCP header; buildMinimalTCPSegment must
// never be reached from this path.
//
// Fail-closed rules, all enforced in WritePackets:
//
//   - a packet whose predicted post-ESP length exceeds innerMTU is dropped, not
//     fragmented and not sent;
//   - a packet TransformOutbound declines to protect (selector mismatch, so it
//     comes back as cleartext) is dropped, never forwarded;
//   - a protected packet that still exceeds innerMTU is dropped;
//   - an unknown or unsupported transform is rejected at construction time.
//
// The endpoint holds exactly one writer, the ESP carrier, and writes to it from
// exactly one place: the tail of WritePackets, after TransformOutbound has
// returned an ESP packet within budget. There is no second path to the tunnel.
//
// MTU() reports the IPv6 minimum, 1280. It is deliberately NOT the ESP segment
// budget: RFC 8200 clause 5 forbids an IPv6 link below 1280, and gvisor's
// ipv6.calculateNetworkMTU rejects it outright. The budget is enforced by
// clamping the peer's advertised MSS instead, which is what actually bounds the
// sender.
type ProtectedLinkEndpoint struct {
	// carrier is the raw IP connection that carries ESP packets. Every write to
	// it happens in WritePackets after a successful TransformOutbound.
	carrier   net.Conn
	transport *Transport
	policy    Policy
	innerMTU  int
	safeMSS   int
	netProto  tcpip.NetworkProtocolNumber

	dispatcherMu sync.RWMutex
	dispatcher   stack.NetworkDispatcher

	stats ProtectedLinkStats

	// ackMu guards the ACK-progress baseline. Only the previous ACK field is held,
	// and only so the next one can be turned into a forward delta; it is never
	// logged or exposed. See observeInboundTCPAck.
	ackMu   sync.Mutex
	ackSeen bool
	lastAck uint32

	closeOnce sync.Once
	closed    chan struct{}
	wg        sync.WaitGroup
}

// protectedTCPConservativeMSSCap is a compatibility ceiling for the new
// protected-TCP path. The transform-derived ceiling remains the hard safety
// bound, but a live path accepted the protected handshake while repeatedly
// failing to acknowledge a 1260-byte data-bearing ESP packet. Capping the TCP
// payload at 1024 keeps the largest data packet well below that observed
// boundary without changing the link MTU, ESP transform, SIP request, or UDP
// path. The endpoint applies the smaller of the derived and compatibility
// ceilings, so transforms that already require a smaller MSS remain unchanged.
const protectedTCPConservativeMSSCap = 1024

// ProtectedLinkStats are de-identified counters for diagnostics. They are counts
// only: no address, SPI, key or payload.
type ProtectedLinkStats struct {
	OutboundProtected   atomic.Uint64
	OutboundOverBudget  atomic.Uint64
	OutboundUnprotected atomic.Uint64
	OutboundErrors      atomic.Uint64
	InboundAccepted     atomic.Uint64
	InboundRejected     atomic.Uint64
	InboundSelectorDrop atomic.Uint64
	HandshakeClamped    atomic.Uint64
	HandshakeFailClosed atomic.Uint64

	// Measured facts about what actually crossed this endpoint. These exist
	// because the previous diagnostic on the TCP path reported a PREDICTION from
	// the UDP framing model, which described a packet that is never built once the
	// MSS clamp splits the request into segments.
	//
	// WritePackets is the only egress and the inbound loop is the only ingress, so
	// these are complete by construction: nothing reaches the carrier or the stack
	// without passing the lines that update them.
	//
	// OutboundDataSegments counts protected packets carrying TCP payload, so a
	// bare ACK or a handshake segment does not inflate the segment count.
	OutboundDataSegments atomic.Uint64
	// OutboundPayloadBytes is the total TCP payload handed to the carrier.
	OutboundPayloadBytes atomic.Uint64
	// MaxInnerPacketLen is the largest ESP packet written. This is the number that
	// answers "did anything exceed the SWu MTU", measured rather than modelled.
	MaxInnerPacketLen atomic.Uint64
	// InboundAckedPayloadBytes is how much of our payload the peer's TCP has
	// acknowledged, derived from the ACK field's forward progress.
	//
	// Only the DELTA is accumulated; no sequence or acknowledgement number is ever
	// stored or logged. That keeps the answer to "was our data accepted" available
	// without recording connection-identifying wire state.
	InboundAckedPayloadBytes atomic.Uint64
	// InboundDataSegments counts inbound segments carrying payload.
	InboundDataSegments atomic.Uint64
}

// ProtectedLinkSnapshot is a plain-value copy of the counters.
type ProtectedLinkSnapshot struct {
	OutboundProtected   uint64
	OutboundOverBudget  uint64
	OutboundUnprotected uint64
	OutboundErrors      uint64
	InboundAccepted     uint64
	InboundRejected     uint64
	InboundSelectorDrop uint64
	HandshakeClamped    uint64
	HandshakeFailClosed uint64

	// Measured, not predicted. See the endpoint fields for why these exist.
	DataSegments      uint64
	DataBytes         uint64
	MaxInnerPacketLen uint64
	AckedBytes        uint64
}

var _ stack.LinkEndpoint = (*ProtectedLinkEndpoint)(nil)

// NewProtectedLinkEndpoint builds an endpoint for an installed policy.
//
// It fails closed when the negotiated transform cannot be modelled, because a
// wrong ESP overhead estimate would silently reintroduce fragmentation.
func NewProtectedLinkEndpoint(carrier net.Conn, transport *Transport, policy Policy, innerMTU int) (*ProtectedLinkEndpoint, error) {
	if carrier == nil {
		return nil, errors.New("ipsec3gpp: protected link requires an ESP carrier")
	}
	if transport == nil {
		return nil, errors.New("ipsec3gpp: protected link requires a transform")
	}
	if innerMTU < header.IPv6MinimumMTU {
		return nil, fmt.Errorf("ipsec3gpp: protected link inner MTU %d is below the IPv6 minimum", innerMTU)
	}
	plan, err := PlanProtectedMSS(policy, innerMTU)
	if err != nil {
		return nil, err
	}
	safeMSS := plan.SafeMSS
	if safeMSS > protectedTCPConservativeMSSCap {
		safeMSS = protectedTCPConservativeMSSCap
	}
	netProto := ipv6.ProtocolNumber
	if len(policy.LocalIP) == 4 {
		netProto = ipv4.ProtocolNumber
	}
	return &ProtectedLinkEndpoint{
		carrier:   carrier,
		transport: transport,
		policy:    policy,
		innerMTU:  innerMTU,
		safeMSS:   safeMSS,
		netProto:  netProto,
		closed:    make(chan struct{}),
	}, nil
}

// SafeMSS is the derived MSS this endpoint advertises and clamps peers to.
func (e *ProtectedLinkEndpoint) SafeMSS() int {
	if e == nil {
		return 0
	}
	return e.safeMSS
}

// NetworkProtocol is the address family the policy is installed for.
func (e *ProtectedLinkEndpoint) NetworkProtocol() tcpip.NetworkProtocolNumber {
	if e == nil {
		return 0
	}
	return e.netProto
}

// Snapshot returns the current counters.
func (e *ProtectedLinkEndpoint) Snapshot() ProtectedLinkSnapshot {
	if e == nil {
		return ProtectedLinkSnapshot{}
	}
	return ProtectedLinkSnapshot{
		OutboundProtected:   e.stats.OutboundProtected.Load(),
		OutboundOverBudget:  e.stats.OutboundOverBudget.Load(),
		OutboundUnprotected: e.stats.OutboundUnprotected.Load(),
		OutboundErrors:      e.stats.OutboundErrors.Load(),
		InboundAccepted:     e.stats.InboundAccepted.Load(),
		InboundRejected:     e.stats.InboundRejected.Load(),
		InboundSelectorDrop: e.stats.InboundSelectorDrop.Load(),
		HandshakeClamped:    e.stats.HandshakeClamped.Load(),
		HandshakeFailClosed: e.stats.HandshakeFailClosed.Load(),

		DataSegments:      e.stats.OutboundDataSegments.Load(),
		DataBytes:         e.stats.OutboundPayloadBytes.Load(),
		MaxInnerPacketLen: e.stats.MaxInnerPacketLen.Load(),
		AckedBytes:        e.stats.InboundAckedPayloadBytes.Load(),
	}
}

// MTU implements stack.LinkEndpoint. See the type comment for why this is the
// IPv6 minimum and not the ESP budget.
func (e *ProtectedLinkEndpoint) MTU() uint32 {
	if e == nil {
		return 0
	}
	return uint32(e.innerMTU)
}

// MaxHeaderLength implements stack.LinkEndpoint. There is no link header: the
// stack hands us complete IP packets.
func (*ProtectedLinkEndpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements stack.LinkEndpoint.
func (*ProtectedLinkEndpoint) LinkAddress() tcpip.LinkAddress { return "" }

// Capabilities implements stack.LinkEndpoint.
//
// Zero is load-bearing: declaring GSO or TSO would let gvisor hand this endpoint
// an unsegmented super-packet, which the ESP transform would protect as one
// oversized packet. Returning no capabilities makes gvisor segment first.
func (*ProtectedLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

// Attach implements stack.LinkEndpoint and starts the inbound pump.
func (e *ProtectedLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	if e == nil {
		return
	}
	e.dispatcherMu.Lock()
	e.dispatcher = dispatcher
	e.dispatcherMu.Unlock()
	if dispatcher == nil {
		return
	}
	e.wg.Add(1)
	go e.inboundLoop()
}

// IsAttached implements stack.LinkEndpoint.
func (e *ProtectedLinkEndpoint) IsAttached() bool {
	if e == nil {
		return false
	}
	e.dispatcherMu.RLock()
	defer e.dispatcherMu.RUnlock()
	return e.dispatcher != nil
}

// Wait implements stack.LinkEndpoint.
func (e *ProtectedLinkEndpoint) Wait() {
	if e == nil {
		return
	}
	e.wg.Wait()
}

// ARPHardwareType implements stack.LinkEndpoint.
func (*ProtectedLinkEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

// AddHeader implements stack.LinkEndpoint.
func (*ProtectedLinkEndpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint.
func (*ProtectedLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close stops the inbound pump. It does not close the carrier: the caller owns
// that, because the same carrier also carries the SIP connection's lifetime.
func (e *ProtectedLinkEndpoint) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() { close(e.closed) })
}

// WritePackets implements stack.LinkWriter. This is the ONLY place that writes
// to the carrier.
func (e *ProtectedLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e == nil || e.carrier == nil || e.transport == nil {
		return 0, &tcpip.ErrClosedForSend{}
	}
	select {
	case <-e.closed:
		return 0, &tcpip.ErrClosedForSend{}
	default:
	}

	written := 0
	for _, pkt := range pkts.AsSlice() {
		cleartext := protectedLinkPacketBytes(pkt)
		if len(cleartext) == 0 {
			continue
		}

		// Predict before protecting. An over-budget packet must never be handed
		// to the transform, because the tunnel writer below it would fragment
		// the result.
		predicted, err := PredictProtectedESPLen(e.policy.FlowC, len(cleartext))
		if err != nil {
			e.stats.OutboundErrors.Add(1)
			return written, &tcpip.ErrInvalidOptionValue{}
		}
		if predicted > e.innerMTU {
			e.stats.OutboundOverBudget.Add(1)
			return written, &tcpip.ErrMessageTooLong{}
		}

		esp, err := e.transport.TransformOutbound(cleartext)
		if err != nil {
			e.stats.OutboundErrors.Add(1)
			return written, &tcpip.ErrInvalidEndpointState{}
		}
		// TransformOutbound passes selector mismatches through unchanged. Such a
		// packet is cleartext and must be dropped, never written.
		if !isESPIPPacket(esp) {
			e.stats.OutboundUnprotected.Add(1)
			return written, &tcpip.ErrInvalidEndpointState{}
		}
		if len(esp) > e.innerMTU {
			e.stats.OutboundOverBudget.Add(1)
			return written, &tcpip.ErrMessageTooLong{}
		}

		if _, err := e.carrier.Write(esp); err != nil {
			e.stats.OutboundErrors.Add(1)
			return written, &tcpip.ErrClosedForSend{}
		}
		e.stats.OutboundProtected.Add(1)
		e.recordOutboundMeasurement(cleartext, len(esp))
		written++
	}
	return written, nil
}

// inboundLoop reads ESP from the carrier, verifies it, clamps the peer's
// handshake MSS on the local plaintext copy, and injects it into the stack.
func (e *ProtectedLinkEndpoint) inboundLoop() {
	defer e.wg.Done()
	buf := make([]byte, protectedLinkReadBufferLen)
	for {
		select {
		case <-e.closed:
			return
		default:
		}
		n, err := e.carrier.Read(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		e.deliverInbound(buf[:n])
	}
}

// deliverInbound is the ingress half. It is separate from the read loop so tests
// can drive it deterministically.
func (e *ProtectedLinkEndpoint) deliverInbound(espPacket []byte) {
	// Reject anything that is not ESP before touching the transform.
	// TransformInbound deliberately passes non-ESP packets through unchanged, so
	// checking afterwards would accept unprotected traffic on this endpoint.
	if !isESPIPPacket(espPacket) {
		e.stats.InboundRejected.Add(1)
		return
	}
	// ESP integrity, replay and SPI lookup all happen here. Nothing downstream
	// may run before this succeeds.
	plain, err := e.transport.TransformInbound(espPacket)
	if err != nil {
		e.stats.InboundRejected.Add(1)
		return
	}
	if !e.matchesInboundSelector(plain) {
		e.stats.InboundSelectorDrop.Add(1)
		return
	}

	// Clamp the peer's advertised MSS on the LOCAL copy only. The verified wire
	// packet is not modified, not re-encrypted and not sent back.
	clamped, result, err := ClampHandshakeMSS(plain, e.safeMSS)
	switch {
	case err != nil:
		// A handshake segment with a missing, duplicated or malformed MSS option
		// is dropped rather than guessed. The connection then fails before any
		// SIP is sent, which is the intended behaviour.
		e.stats.HandshakeFailClosed.Add(1)
		return
	case result.Applied:
		e.stats.HandshakeClamped.Add(1)
		plain = clamped
	}

	// Record how far the peer's TCP has acknowledged our payload. This runs only
	// after ESP integrity, replay and the selector check, so a forged or foreign
	// packet cannot move the counter.
	e.observeInboundTCPAck(plain)

	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil {
		e.stats.InboundRejected.Add(1)
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte(nil), plain...)),
	})
	dispatcher.DeliverNetworkPacket(e.netProto, pkt)
	pkt.DecRef()
	e.stats.InboundAccepted.Add(1)
}

// observeOutboundTCPSegment records the measured facts about one protected
// packet: whether it carried TCP payload, how much, and how large the resulting
// ESP packet was.
//
// It is called only after a successful carrier write, so the counters describe
// what actually left the endpoint rather than what was attempted.
func (e *ProtectedLinkEndpoint) observeOutboundTCPSegment(cleartext []byte, espLen int) {
	// The largest ESP packet is the number that answers "did anything exceed the
	// SWu MTU". Recorded for every packet, payload-bearing or not.
	for {
		current := e.stats.MaxInnerPacketLen.Load()
		if uint64(espLen) <= current {
			break
		}
		if e.stats.MaxInnerPacketLen.CompareAndSwap(current, uint64(espLen)) {
			break
		}
	}

	payloadLen, ok := tcpPayloadLen(cleartext)
	if !ok || payloadLen <= 0 {
		// A bare ACK, SYN or FIN. Counting it as a data segment would inflate the
		// segment count and hide how many segments the request really took.
		return
	}
	e.stats.OutboundDataSegments.Add(1)
	e.stats.OutboundPayloadBytes.Add(uint64(payloadLen))
}

// observeInboundTCPAck accumulates how much of our payload the peer has
// acknowledged.
//
// Only the forward DELTA between successive ACK fields is accumulated. The
// acknowledgement number itself is never stored or logged: the question this
// answers is "was our data accepted", which a byte total answers without
// recording connection-identifying wire state.
//
// A wrapped or retreating ACK contributes nothing rather than a huge bogus delta.
func (e *ProtectedLinkEndpoint) observeInboundTCPAck(plain []byte) {
	ack, hasAck, payloadLen, ok := tcpAckAndPayload(plain)
	if !ok {
		return
	}
	if payloadLen > 0 {
		e.stats.InboundDataSegments.Add(1)
	}
	if !hasAck {
		return
	}

	e.ackMu.Lock()
	defer e.ackMu.Unlock()
	if !e.ackSeen {
		// The first ACK is the connection's baseline. Counting the absolute value
		// would report the peer's initial sequence number as acknowledged bytes.
		e.ackSeen = true
		e.lastAck = ack
		return
	}
	delta := ack - e.lastAck
	// A retreat or a wrap shows up as a delta above half the sequence space.
	if delta == 0 || delta > 1<<31 {
		return
	}
	e.lastAck = ack
	e.stats.InboundAckedPayloadBytes.Add(uint64(delta))
}

// recordOutboundMeasurement records what actually went to the carrier.
//
// It runs after a successful write, so the counters describe bytes that really
// left rather than bytes that were merely intended. innerLen is the ESP packet
// length; only its maximum is kept, because that single number answers "did
// anything exceed the SWu MTU" without retaining a per-packet history.
func (e *ProtectedLinkEndpoint) recordOutboundMeasurement(cleartext []byte, innerLen int) {
	if e == nil {
		return
	}
	if innerLen > 0 {
		// Monotonic maximum. A plain Store would let a later small packet erase the
		// evidence of an earlier large one.
		for {
			current := e.stats.MaxInnerPacketLen.Load()
			if uint64(innerLen) <= current {
				break
			}
			if e.stats.MaxInnerPacketLen.CompareAndSwap(current, uint64(innerLen)) {
				break
			}
		}
	}
	payloadLen, ok := tcpPayloadLen(cleartext)
	if !ok || payloadLen <= 0 {
		// A bare ACK or handshake segment. Counting it as a data segment would make
		// the segment count useless for judging how the request was split.
		return
	}
	e.stats.OutboundDataSegments.Add(1)
	e.stats.OutboundPayloadBytes.Add(uint64(payloadLen))
}

// recordInboundAckProgress accumulates how much of OUR payload the peer has
// acknowledged.
//
// Only the forward delta between consecutive ACK fields is added, and the ACK
// value itself is kept solely to compute the next delta - it is never logged,
// never exported and never included in a snapshot. That yields "were our bytes
// accepted" without recording connection-identifying wire state.
//
// The comparison is modulo 2^32 via seqnum arithmetic, so a wrap does not
// register as a huge jump backwards.
func (e *ProtectedLinkEndpoint) recordInboundAckProgress(plain []byte) {
	if e == nil {
		return
	}
	ack, hasAck, payloadLen, ok := tcpAckAndPayload(plain)
	if !ok {
		return
	}
	if payloadLen > 0 {
		e.stats.InboundDataSegments.Add(1)
	}
	if !hasAck {
		return
	}
	e.ackMu.Lock()
	defer e.ackMu.Unlock()
	if !e.ackSeen {
		// The first ACK is the handshake's; it acknowledges our SYN, not payload.
		e.ackSeen = true
		e.lastAck = ack
		return
	}
	delta := ack - e.lastAck
	// A delta with the high bit set is a backwards move (a duplicate or reordered
	// ACK), which acknowledges nothing new.
	if delta == 0 || delta&0x80000000 != 0 {
		return
	}
	e.lastAck = ack
	e.stats.InboundAckedPayloadBytes.Add(uint64(delta))
}

// tcpPayloadLen returns the TCP payload length of an IPv4/IPv6 packet.
func tcpPayloadLen(packet []byte) (int, bool) {
	_, _, payloadLen, ok := tcpAckAndPayloadFrom(packet)
	return payloadLen, ok
}

// tcpAckAndPayload returns the ACK field, whether the ACK flag was set, and the
// payload length.
func tcpAckAndPayload(packet []byte) (ack uint32, hasAck bool, payloadLen int, ok bool) {
	return tcpAckAndPayloadFrom(packet)
}

// tcpAckAndPayloadFrom parses just enough of an IP+TCP packet to answer both
// questions. It never retains the parsed values.
func tcpAckAndPayloadFrom(packet []byte) (ack uint32, hasAck bool, payloadLen int, ok bool) {
	parsed, err := parseIPPacket(packet)
	if err != nil || parsed.nextHeader != ipProtoTCP {
		return 0, false, 0, false
	}
	seg := parsed.transportPayload
	if len(seg) < 20 {
		return 0, false, 0, false
	}
	headerLen := int(seg[12]>>4) * 4
	if headerLen < 20 || headerLen > len(seg) {
		return 0, false, 0, false
	}
	const ackFlag = 0x10
	ack = binary.BigEndian.Uint32(seg[8:12])
	hasAck = seg[13]&ackFlag != 0
	return ack, hasAck, len(seg) - headerLen, true
}

// matchesInboundSelector checks the decrypted packet against the installed
// policy: it must come from the negotiated P-CSCF to us, and land on one of the
// two protected port pairs.
func (e *ProtectedLinkEndpoint) matchesInboundSelector(plain []byte) bool {
	parsed, err := parseIPPacket(plain)
	if err != nil {
		return false
	}
	if !ipEqual(parsed.src, e.policy.RemoteIP) || !ipEqual(parsed.dst, e.policy.LocalIP) {
		return false
	}
	if parsed.nextHeader != ipProtoTCP && parsed.nextHeader != ipProtoUDP {
		return false
	}
	// FlowC carries UE-client to P-CSCF-server traffic, so its responses arrive
	// from RemotePort to LocalPort. FlowS is the reverse role.
	if parsed.srcPort == e.policy.FlowC.RemotePort && parsed.dstPort == e.policy.FlowC.LocalPort {
		return true
	}
	if parsed.srcPort == e.policy.FlowS.RemotePort && parsed.dstPort == e.policy.FlowS.LocalPort {
		return true
	}
	return false
}

// protectedLinkReadBufferLen bounds one inbound ESP read. The carrier is a raw
// IP connection in packet mode, so one read is one packet.
const protectedLinkReadBufferLen = 65535

func protectedLinkPacketBytes(pkt *stack.PacketBuffer) []byte {
	if pkt == nil {
		return nil
	}
	v := pkt.ToBuffer()
	defer v.Release()
	return append([]byte(nil), v.Flatten()...)
}

// isESPIPPacket reports whether an IP packet's next header is ESP.
func isESPIPPacket(packet []byte) bool {
	switch {
	case len(packet) >= 40 && packet[0]>>4 == 6:
		return packet[6] == ipProtoESP
	case len(packet) >= 20 && packet[0]>>4 == 4:
		return packet[9] == ipProtoESP
	default:
		return false
	}
}
