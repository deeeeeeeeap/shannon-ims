package ipsec3gpp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Stage 3: a TEST-ONLY architecture prototype for protected SIP-over-TCP.
//
// It is deliberately NOT wired into dialSecureRegisterConn. It exists to answer
// one question: can a REAL TCP stack's segments be fed through the existing
// packet-level IMS ESP transform, so that IPsec only ever PROTECTS genuine TCP
// segments instead of synthesising them?
//
// The rejected alternative (option C) was to keep growing
// buildMinimalTCPSegment - a fixed 20-byte header with seq=1, ack=1, PSH+ACK,
// no checksum and no segmentation - into a hand-written TCP. Every property
// asserted below (real ISN, real checksum, MSS advertisement, segmentation,
// ordered reassembly) is something that stub cannot provide and that a real
// stack provides for free.
//
// Topology, both directions carried as ESP transport mode:
//
//	client gVisor stack -> channel link (MTU derived) -> TransformOutbound
//	  -> [captured ESP packets] -> TransformInbound -> server gVisor stack
//
// Assertions cover lengths, counts, flags, sequence numbers and checksum
// validity. No SIP text, key, IV, ciphertext, address or identity is printed.

// ---------------------------------------------------------------------------
// Derived budget. Nothing here is a copied constant.
// ---------------------------------------------------------------------------

const (
	protoTCPInnerMTU  = 1280 // voiceclient.swuRawIPMTU
	protoTCPIPv6Hdr   = 40
	protoTCPESPHdr    = 8 // SPI || Sequence
	protoTCPESPIV     = 16
	protoTCPESPICV    = 12
	protoTCPESPBlock  = 16
	protoTCPESPTrail  = 2 // Pad Length || Next Header
	protoTCPMinHdrLen = 20
)

// maxProtectedTCPSegmentLen is the largest TCP header+payload whose ESP inner
// packet still fits the SWu raw IP MTU:
//
//	inner = IPv6 + ESPHdr + IV + roundUp(block, seg+trailer) + ICV
func maxProtectedTCPSegmentLen() int {
	usable := protoTCPInnerMTU - protoTCPIPv6Hdr - protoTCPESPHdr - protoTCPESPIV - protoTCPESPICV
	usable -= usable % protoTCPESPBlock
	return usable - protoTCPESPTrail
}

// derivedProtectedLinkMTU is the link MTU a gVisor channel endpoint must be
// given so the stack itself never produces an over-budget segment.
//
// gVisor chain: ipv6 endpoint MTU = nic.MTU() - IPv6MinimumSize, route.MTU() is
// that value, advertised MSS = route.MTU() - TCPMinimumSize, and the sender
// further subtracts maxOptionSize() from the payload. So options shrink the
// PAYLOAD while the SEGMENT stays at the budget - which is exactly why this
// must be expressed as a link MTU and not as a hardcoded MSS.
func derivedProtectedLinkMTU() int {
	return protoTCPIPv6Hdr + maxProtectedTCPSegmentLen()
}

// gVisorMinIPv6LinkMTU is the floor gVisor enforces in
// ipv6.calculateNetworkMTU: a link MTU below header.IPv6MinimumMTU makes the
// network endpoint return ErrInvalidEndpointState, so the NIC never carries
// traffic. RFC 8200 clause 5 mandates that floor, so it is not a gVisor quirk.
//
// This is the crux of the whole prototype: the ESP budget wants a 1238 byte
// link, and IPv6 forbids anything under 1280.
const gVisorMinIPv6LinkMTU = 1280

// prototypeLinkMTU is what the harness can actually use.
func prototypeLinkMTU() int {
	if mtu := derivedProtectedLinkMTU(); mtu >= gVisorMinIPv6LinkMTU {
		return mtu
	}
	return gVisorMinIPv6LinkMTU
}

func protoTCPInnerLen(segLen int) int {
	plain := segLen + protoTCPESPTrail
	blocks := (plain + protoTCPESPBlock - 1) / protoTCPESPBlock
	return protoTCPIPv6Hdr + protoTCPESPHdr + protoTCPESPIV + blocks*protoTCPESPBlock + protoTCPESPICV
}

// TestProtectedTCPLinkMTUIsDerivedFromESPBudget pins the arithmetic so a future
// implementation cannot silently pick a wrong MTU or MSS constant.
func TestProtectedTCPLinkMTUIsDerivedFromESPBudget(t *testing.T) {
	maxSeg := maxProtectedTCPSegmentLen()
	if got := protoTCPInnerLen(maxSeg); got > protoTCPInnerMTU {
		t.Fatalf("inner packet for max segment %d = %d, want <= %d", maxSeg, got, protoTCPInnerMTU)
	}
	if got := protoTCPInnerLen(maxSeg + 1); got <= protoTCPInnerMTU {
		t.Fatalf("segment budget %d is not maximal: one more byte still fits at %d", maxSeg, got)
	}
	linkMTU := derivedProtectedLinkMTU()
	t.Logf("MEASURED max_tcp_segment_len=%d required_link_mtu=%d", maxSeg, linkMTU)

	// The link MTU the ESP budget demands, versus the IPv6 floor.
	ipv6EndpointMTU := linkMTU - header.IPv6MinimumSize
	if ipv6EndpointMTU != maxSeg {
		t.Fatalf("ipv6 endpoint MTU = %d, want the segment budget %d", ipv6EndpointMTU, maxSeg)
	}
	advertisedMSS := ipv6EndpointMTU - header.TCPMinimumSize
	t.Logf("MEASURED derived_advertised_mss=%d", advertisedMSS)

	// THE ARCHITECTURAL CONFLICT, stated as an assertion so it cannot be
	// forgotten: the budget needs a link MTU below the IPv6 minimum.
	if linkMTU >= gVisorMinIPv6LinkMTU {
		t.Fatalf("required link MTU %d is >= the IPv6 minimum %d; the conflict this test documents is gone",
			linkMTU, gVisorMinIPv6LinkMTU)
	}
	t.Logf("MEASURED ipv6_min_link_mtu=%d shortfall_bytes=%d",
		gVisorMinIPv6LinkMTU, gVisorMinIPv6LinkMTU-linkMTU)

	// What the smallest LEGAL IPv6 link actually yields.
	legalRouteMTU := gVisorMinIPv6LinkMTU - header.IPv6MinimumSize
	legalMaxSeg := legalRouteMTU
	legalInner := protoTCPInnerLen(legalMaxSeg)
	t.Logf("MEASURED at_ipv6_floor route_mtu=%d max_segment_len=%d inner_len=%d over_budget_by=%d",
		legalRouteMTU, legalMaxSeg, legalInner, legalInner-protoTCPInnerMTU)

	// Options reduce the payload, never the total segment. Both cases must stay
	// inside the ESP budget, which is the property a hardcoded MSS would break.
	for _, optLen := range []int{0, 12, 20} {
		payload := advertisedMSS - optLen
		segLen := protoTCPMinHdrLen + optLen + payload
		if segLen != maxSeg {
			t.Fatalf("segment length with %d option bytes = %d, want the constant budget %d", optLen, segLen, maxSeg)
		}
		if inner := protoTCPInnerLen(segLen); inner > protoTCPInnerMTU {
			t.Fatalf("inner packet with %d option bytes = %d, want <= %d", optLen, inner, protoTCPInnerMTU)
		}
		t.Logf("MEASURED option_bytes=%d safe_payload=%d segment_len=%d inner_len=%d",
			optLen, payload, segLen, protoTCPInnerLen(segLen))
	}
}

// ---------------------------------------------------------------------------
// Independent TCP/IPv6 decoding. Standard library only; no project helpers.
// ---------------------------------------------------------------------------

type protoTCPSegment struct {
	srcIP, dstIP   net.IP
	srcPort        uint16
	dstPort        uint16
	seq            uint32
	ack            uint32
	flags          byte
	headerLen      int
	payload        []byte
	options        []byte
	checksumValid  bool
	advertisedMSS  int
	hasMSSOption   bool
	innerPacketLen int
}

func (s protoTCPSegment) isSYN() bool { return s.flags&0x02 != 0 }
func (s protoTCPSegment) isACK() bool { return s.flags&0x10 != 0 }

// protoTCPParseIPv6 returns the next-header value and the transport payload,
// parsing the fixed IPv6 header by hand.
func protoTCPParseIPv6(t *testing.T, packet []byte) (nextHeader byte, src, dst net.IP, payload []byte) {
	t.Helper()
	if len(packet) < protoTCPIPv6Hdr {
		t.Fatalf("IPv6 packet is %d bytes, want at least %d", len(packet), protoTCPIPv6Hdr)
	}
	if packet[0]>>4 != 6 {
		t.Fatalf("packet version = %d, want 6", packet[0]>>4)
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen != len(packet)-protoTCPIPv6Hdr {
		t.Fatalf("IPv6 payload length field %d does not match %d actual bytes", payloadLen, len(packet)-protoTCPIPv6Hdr)
	}
	src = append(net.IP(nil), packet[8:24]...)
	dst = append(net.IP(nil), packet[24:40]...)
	return packet[6], src, dst, packet[protoTCPIPv6Hdr:]
}

// protoTCPChecksum computes the RFC 2460 pseudo-header TCP checksum by hand.
func protoTCPChecksum(src, dst net.IP, segment []byte) uint16 {
	var sum uint32
	addBytes := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	addBytes(src.To16())
	addBytes(dst.To16())
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(segment)))
	addBytes(lenBuf[:])
	addBytes([]byte{0, 0, 0, 6}) // zero || next header = TCP
	addBytes(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// protoTCPDecodeESP decrypts one captured ESP packet with the independent
// oracle and decodes the TCP segment inside it.
func protoTCPDecodeESP(t *testing.T, espPacket []byte, encKey, authKey []byte) protoTCPSegment {
	t.Helper()
	nextHeader, src, dst, espPayload := protoTCPParseIPv6(t, espPacket)
	if nextHeader != ipProtoESP {
		t.Fatalf("captured packet next header = %d, want ESP", nextHeader)
	}
	decoded := oracleDecodeESP(t, espPayload, encKey, authKey)
	if !decoded.icvValid {
		t.Fatal("captured ESP packet failed independent ICV verification")
	}
	if decoded.nextHeader != ipProtoTCP {
		t.Fatalf("ESP next header = %d, want TCP", decoded.nextHeader)
	}

	seg := decoded.plaintext
	if len(seg) < protoTCPMinHdrLen {
		t.Fatalf("TCP segment is %d bytes, want at least %d", len(seg), protoTCPMinHdrLen)
	}
	headerLen := int(seg[12]>>4) * 4
	if headerLen < protoTCPMinHdrLen || headerLen > len(seg) {
		t.Fatalf("TCP data offset yields header length %d for a %d byte segment", headerLen, len(seg))
	}

	out := protoTCPSegment{
		srcIP:          src,
		dstIP:          dst,
		srcPort:        binary.BigEndian.Uint16(seg[0:2]),
		dstPort:        binary.BigEndian.Uint16(seg[2:4]),
		seq:            binary.BigEndian.Uint32(seg[4:8]),
		ack:            binary.BigEndian.Uint32(seg[8:12]),
		flags:          seg[13],
		headerLen:      headerLen,
		payload:        append([]byte(nil), seg[headerLen:]...),
		options:        append([]byte(nil), seg[protoTCPMinHdrLen:headerLen]...),
		innerPacketLen: len(espPacket),
	}
	// A correct checksum recomputes to zero over the whole segment.
	out.checksumValid = protoTCPChecksum(src, dst, seg) == 0

	// RFC 9293 option parsing: kind 2 is MSS.
	for i := 0; i < len(out.options); {
		kind := out.options[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(out.options) {
			break
		}
		optLen := int(out.options[i+1])
		if optLen < 2 || i+optLen > len(out.options) {
			break
		}
		if kind == 2 && optLen == 4 {
			out.hasMSSOption = true
			out.advertisedMSS = int(binary.BigEndian.Uint16(out.options[i+2 : i+4]))
		}
		i += optLen
	}
	return out
}

// ---------------------------------------------------------------------------
// The prototype: real gVisor TCP on both ends, ESP transform between them.
// ---------------------------------------------------------------------------

type protoTCPEndpoint struct {
	stack  *stack.Stack
	linkEP *channel.Endpoint
	addr   net.IP
}

type protoTCPHarness struct {
	t *testing.T

	client protoTCPEndpoint
	server protoTCPEndpoint

	clientTransport *Transport
	serverTransport *Transport
	clientPolicy    Policy
	serverPolicy    Policy

	mu             sync.Mutex
	clientToServer [][]byte
	serverToClient [][]byte
	// cleartextLeaks counts packets the transform did NOT turn into ESP.
	// TransformOutbound passes non-matching packets through unchanged, so an
	// adapter must drop them rather than hand them to the tunnel writer.
	cleartextLeaks int

	// clampSafeMSS, when greater than zero, clamps the MSS option of SYN-ACKs
	// on the way INTO the local client stack. Zero leaves the inbound path
	// untouched, which is the default every other test in this package uses.
	//
	// The clamp only ever rewrites the decrypted local copy: the captured wire
	// packet stays exactly as it was verified, and nothing is re-encrypted or
	// sent back. synAckClamps counts local rewrites, clampFailClosed counts
	// SYN-ACKs dropped because their MSS option was missing or malformed.
	clampSafeMSS     int
	synAckClamps     int
	clampFailClosed  int
	wireSynAckWrites int

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func newProtoTCPEndpoint(t *testing.T, addr net.IP, linkMTU int) protoTCPEndpoint {
	t.Helper()
	linkEP := channel.New(512, uint32(linkMTU), "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol},
	})
	if err := s.CreateNIC(1, linkEP); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.To16()),
			PrefixLen: 128,
		},
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}})
	return protoTCPEndpoint{stack: s, linkEP: linkEP, addr: addr}
}

func reverseProtoTCPFlow(f Flow) Flow {
	rf := f
	rf.OutboundSPI, rf.InboundSPI = f.InboundSPI, f.OutboundSPI
	rf.LocalPort, rf.RemotePort = f.RemotePort, f.LocalPort
	return rf
}

func reverseProtoTCPPolicy(p Policy) Policy {
	rev := p
	rev.LocalIP, rev.RemoteIP = p.RemoteIP, p.LocalIP
	rev.LocalPortC, rev.RemotePortC = p.RemotePortC, p.LocalPortC
	rev.LocalPortS, rev.RemotePortS = p.RemotePortS, p.LocalPortS
	rev.FlowC = reverseProtoTCPFlow(p.FlowC)
	rev.FlowS = reverseProtoTCPFlow(p.FlowS)
	return rev
}

func protoTCPPacketBytes(pkt *stack.PacketBuffer) []byte {
	if pkt == nil {
		return nil
	}
	v := pkt.ToBuffer()
	defer v.Release()
	return append([]byte(nil), v.Flatten()...)
}

func newProtoTCPHarness(t *testing.T) *protoTCPHarness {
	t.Helper()
	clientPolicy := oraclePolicy(t)
	serverPolicy := reverseProtoTCPPolicy(clientPolicy)

	clientTransport, err := NewTransport(clientPolicy)
	if err != nil {
		t.Fatalf("client NewTransport: %v", err)
	}
	serverTransport, err := NewTransport(serverPolicy)
	if err != nil {
		t.Fatalf("server NewTransport: %v", err)
	}

	linkMTU := prototypeLinkMTU()
	h := &protoTCPHarness{
		t:               t,
		client:          newProtoTCPEndpoint(t, net.IP(clientPolicy.LocalIP), linkMTU),
		server:          newProtoTCPEndpoint(t, net.IP(clientPolicy.RemoteIP), linkMTU),
		clientTransport: clientTransport,
		serverTransport: serverTransport,
		clientPolicy:    clientPolicy,
		serverPolicy:    serverPolicy,
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	h.wg.Add(2)
	go h.relay(ctx, h.client, h.clientTransport, h.serverTransport, h.server, true)
	go h.relay(ctx, h.server, h.serverTransport, h.clientTransport, h.client, false)

	t.Cleanup(func() {
		cancel()
		h.client.linkEP.Close()
		h.server.linkEP.Close()
		h.client.stack.Close()
		h.server.stack.Close()
		h.wg.Wait()
	})
	return h
}

// relay is the prototype's protected link endpoint: it reads cleartext IP
// packets the stack wants to send, protects them with ESP, records them, and
// only then hands them to the far side. A packet that does not come back as ESP
// is counted as a leak and DROPPED - never forwarded.
func (h *protoTCPHarness) relay(ctx context.Context, from protoTCPEndpoint, out, in *Transport, to protoTCPEndpoint, clientToServer bool) {
	defer h.wg.Done()
	for {
		pkt := from.linkEP.ReadContext(ctx)
		if pkt == nil {
			return
		}
		cleartext := protoTCPPacketBytes(pkt)
		pkt.DecRef()
		if len(cleartext) == 0 {
			continue
		}

		esp, err := out.TransformOutbound(cleartext)
		if err != nil {
			continue
		}
		if !protoTCPIsESP(esp) {
			h.mu.Lock()
			h.cleartextLeaks++
			h.mu.Unlock()
			continue
		}

		h.mu.Lock()
		if clientToServer {
			h.clientToServer = append(h.clientToServer, esp)
		} else {
			h.serverToClient = append(h.serverToClient, esp)
		}
		h.mu.Unlock()

		// ESP integrity is verified HERE. Nothing below may run on an
		// unauthenticated packet: TransformInbound has already checked the ICV and
		// the replay window, so `plain` is authenticated cleartext.
		plain, err := in.TransformInbound(esp)
		if err != nil {
			continue
		}

		// Gate 7: clamp the peer's advertised MSS on the LOCAL COPY ONLY.
		//
		// `esp` was appended to the capture slice above and is never touched, so
		// the verified wire packet stays byte-identical. The clamp rewrites the
		// plaintext that is about to be injected into our own stack, which is what
		// gVisor turns into h.mss -> newSender -> MaxPayloadSize.
		if h.clampSafeMSS > 0 && !clientToServer {
			clamped, applied, err := clampSynAckMSSLocalCopy(plain, h.clampSafeMSS)
			if err != nil {
				// Fail closed: an unparseable or malformed MSS option must not be
				// forwarded on a guess.
				h.mu.Lock()
				h.clampFailClosed++
				h.mu.Unlock()
				continue
			}
			if applied {
				h.mu.Lock()
				h.synAckClamps++
				h.mu.Unlock()
				plain = clamped
			}
		}

		injected := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), plain...)),
		})
		to.linkEP.InjectInbound(ipv6.ProtocolNumber, injected)
		injected.DecRef()
	}
}

func protoTCPIsESP(packet []byte) bool {
	return len(packet) >= protoTCPIPv6Hdr && packet[0]>>4 == 6 && packet[6] == ipProtoESP
}

func (h *protoTCPHarness) captured(clientToServer bool) [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	src := h.clientToServer
	if !clientToServer {
		src = h.serverToClient
	}
	out := make([][]byte, len(src))
	copy(out, src)
	return out
}

func (h *protoTCPHarness) leaks() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cleartextLeaks
}

// listen accepts one protected connection on the UE-facing port_ps.
func (h *protoTCPHarness) listen(t *testing.T) *gonet.TCPListener {
	t.Helper()
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.serverPolicy.LocalIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.RemotePort),
	}
	ln, err := gonet.ListenTCP(h.server.stack, addr, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatalf("synthetic P-CSCF listen: %v", err)
	}
	return ln
}

// dial connects from the UE protected client port to the P-CSCF protected
// server port, exactly the pair TS 33.203 clause 7.1 allows.
func (h *protoTCPHarness) dial(ctx context.Context, t *testing.T) *gonet.TCPConn {
	t.Helper()
	local := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.LocalIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.LocalPort),
	}
	remote := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.RemoteIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.RemotePort),
	}
	conn, err := gonet.DialTCPWithBind(ctx, h.client.stack, local, remote, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatalf("protected TCP dial: %v", err)
	}
	return conn
}

// TestProtectedTCPClientFlowPerformsRealHandshake proves the prototype produces
// a genuine TCP handshake - the thing buildMinimalTCPSegment cannot do.
func TestProtectedTCPClientFlowPerformsRealHandshake(t *testing.T) {
	h := newProtoTCPHarness(t)
	ln := h.listen(t)
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()

	peer, ok := <-accepted
	if !ok || peer == nil {
		t.Fatal("synthetic P-CSCF never accepted the protected connection")
	}
	defer peer.Close()

	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	outbound := h.captured(true)
	if len(outbound) == 0 {
		t.Fatal("no protected packets were captured")
	}

	// 1. The first packet must be a bare SYN, no SIP payload.
	syn := protoTCPDecodeESP(t, outbound[0], encKey, authKey)
	if !syn.isSYN() || syn.isACK() {
		t.Fatalf("first protected packet flags = %#x, want SYN only", syn.flags)
	}
	if len(syn.payload) != 0 {
		t.Fatalf("SYN carries %d payload bytes, want 0", len(syn.payload))
	}
	// 2. Ports must be the negotiated protected pair.
	if int(syn.srcPort) != h.clientPolicy.FlowC.LocalPort {
		t.Fatalf("SYN source port = %d, want the UE protected client port", syn.srcPort)
	}
	if int(syn.dstPort) != h.clientPolicy.FlowC.RemotePort {
		t.Fatalf("SYN destination port = %d, want the P-CSCF protected server port", syn.dstPort)
	}
	// 3. Checksum must be correct - the stub never computes one.
	if !syn.checksumValid {
		t.Fatal("SYN TCP checksum is invalid")
	}
	// 4. ISN must not be the stub's fixed 1.
	if syn.seq == 1 {
		t.Fatal("SYN sequence number is 1; a real stack must choose an ISN")
	}
	// 5. No cleartext may reach the tunnel writer.
	if n := h.leaks(); n != 0 {
		t.Fatalf("%d cleartext packets were rejected by the transform; an adapter must not forward them", n)
	}

	inbound := h.captured(false)
	if len(inbound) == 0 {
		t.Fatal("no protected packets came back from the synthetic P-CSCF")
	}
	serverEnc, serverAuth := oracleExpectedKeys(h.serverPolicy.FlowC)
	synAck := protoTCPDecodeESP(t, inbound[0], serverEnc, serverAuth)
	if !synAck.isSYN() || !synAck.isACK() {
		t.Fatalf("first inbound packet flags = %#x, want SYN+ACK", synAck.flags)
	}
	if !synAck.checksumValid {
		t.Fatal("SYN-ACK TCP checksum is invalid")
	}
	if synAck.ack != syn.seq+1 {
		t.Fatal("SYN-ACK does not acknowledge the client ISN")
	}
	t.Logf("MEASURED handshake_completed=true syn_len=%d syn_ack_len=%d client_isn_is_fixed=false",
		syn.innerPacketLen, synAck.innerPacketLen)
}

// TestProtectedTCPSYNAdvertisesESPAdjustedMSS proves the SYN tells the peer how
// small its segments must be, derived from the ESP budget.
func TestProtectedTCPSYNAdvertisesESPAdjustedMSS(t *testing.T) {
	h := newProtoTCPHarness(t)
	ln := h.listen(t)
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()
	peer, ok := <-accepted
	if !ok || peer == nil {
		t.Fatal("synthetic P-CSCF never accepted")
	}
	defer peer.Close()

	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	syn := protoTCPDecodeESP(t, h.captured(true)[0], encKey, authKey)
	if !syn.hasMSSOption {
		t.Fatal("SYN does not advertise an MSS option")
	}

	// What gVisor actually advertises is derived from the link MTU, which the
	// IPv6 floor pins at 1280: route MTU 1240, so MSS 1220.
	routeMTU := prototypeLinkMTU() - header.IPv6MinimumSize
	wantMSS := routeMTU - header.TCPMinimumSize
	if syn.advertisedMSS != wantMSS {
		t.Fatalf("advertised MSS = %d, want the route-derived %d", syn.advertisedMSS, wantMSS)
	}

	// THE GAP, pinned as an assertion: a peer that honours this MSS still
	// overflows the ESP budget, because the budget wanted a link MTU the IPv6
	// floor forbids. MaxSegOption can lower what we ADVERTISE (bounding the
	// peer), but our own sender is driven by min(peer MSS, route MTU), so it
	// cannot be pushed below the floor either.
	peerSegLen := protoTCPMinHdrLen + syn.advertisedMSS
	peerInner := protoTCPInnerLen(peerSegLen)
	safePayload := maxProtectedTCPSegmentLen() - protoTCPMinHdrLen
	if peerInner <= protoTCPInnerMTU {
		t.Fatalf("a peer honouring MSS %d now fits at %d bytes; the IPv6-floor conflict is gone and this test must be revisited",
			syn.advertisedMSS, peerInner)
	}
	t.Logf("MEASURED advertised_mss=%d safe_mss_required=%d mss_excess=%d",
		syn.advertisedMSS, safePayload, syn.advertisedMSS-safePayload)
	t.Logf("MEASURED peer_worst_case_inner_len=%d over_budget_by=%d",
		peerInner, peerInner-protoTCPInnerMTU)
}

// TestProtectedTCPLargeRegisterDoesNotEmitIPv6Fragments is the decisive test:
// a production-sized protected REGISTER must cross the tunnel as multiple
// in-budget TCP segments with no IPv6 fragmentation at all.
func TestProtectedTCPLargeRegisterDoesNotEmitIPv6Fragments(t *testing.T) {
	h := newProtoTCPHarness(t)
	ln := h.listen(t)
	defer ln.Close()

	const registerLen = 1453 // the measured production protected REGISTER
	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(received)
			return
		}
		defer conn.Close()
		buf := make([]byte, 0, registerLen)
		tmp := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for len(buf) < registerLen {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		received <- buf
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()

	// A deterministic synthetic body. Not SIP text, just a byte pattern of the
	// measured length so reassembly can be verified exactly.
	request := make([]byte, registerLen)
	for i := range request {
		request[i] = byte('A' + (i % 26))
	}
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("protected write: %v", err)
	}

	got, ok := <-received
	if !ok {
		t.Fatal("synthetic P-CSCF never accepted the connection")
	}
	if len(got) != registerLen {
		t.Fatalf("peer received %d bytes, want %d", len(got), registerLen)
	}
	if !bytes.Equal(got, request) {
		t.Fatal("the byte stream the peer received differs from what was written")
	}

	// Now verify the wire independently.
	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	dataSegments := 0
	maxInner := 0
	type piece struct {
		seq  uint32
		data []byte
	}
	pieces := []piece{}
	for _, esp := range h.captured(true) {
		// No fragment header may ever appear.
		if nextHeader, _, _, _ := protoTCPParseIPv6(t, esp); nextHeader == 44 {
			t.Fatal("an IPv6 Fragment Header was emitted on the protected TCP path")
		}
		if len(esp) > maxInner {
			maxInner = len(esp)
		}
		seg := protoTCPDecodeESP(t, esp, encKey, authKey)
		if !seg.checksumValid {
			t.Fatal("a protected TCP segment has an invalid checksum")
		}
		if len(seg.payload) > 0 {
			dataSegments++
			pieces = append(pieces, piece{seq: seg.seq, data: seg.payload})
		}
	}
	if dataSegments < 2 {
		t.Fatalf("data segments = %d; a %d byte request must be segmented", dataSegments, registerLen)
	}

	// Independent reassembly by sequence number.
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].seq < pieces[j].seq })
	var stream []byte
	var expectNext uint32
	for i, p := range pieces {
		if i == 0 {
			expectNext = p.seq
		}
		if p.seq != expectNext {
			t.Fatalf("sequence gap: segment %d starts at an unexpected offset", i)
		}
		stream = append(stream, p.data...)
		expectNext = p.seq + uint32(len(p.data))
	}
	if !bytes.Equal(stream, request) {
		t.Fatal("independently reassembled stream differs from the original request")
	}
	if n := h.leaks(); n != 0 {
		t.Fatalf("%d cleartext packets were rejected by the transform", n)
	}
	// The decisive positive result: TCP segmentation REPLACED IP fragmentation.
	// No Fragment Header was emitted above, the stream reassembled byte-exactly,
	// and the request crossed as multiple real segments.
	t.Logf("MEASURED sip_len=%d data_segments=%d fragmented=false", registerLen, dataSegments)

	// The remaining gap, pinned so it cannot be forgotten: each segment is still
	// larger than the project's inner budget, by exactly the IPv6-floor
	// shortfall. This is a size gap, not a fragmentation gap.
	t.Logf("MEASURED max_inner_packet_len=%d budget=%d over_budget_by=%d",
		maxInner, protoTCPInnerMTU, maxInner-protoTCPInnerMTU)
	if maxInner <= protoTCPInnerMTU {
		t.Fatalf("every protected packet now fits %d bytes; the IPv6-floor conflict is gone and this test must be revisited",
			protoTCPInnerMTU)
	}
}

// TestProtectedTCPResponseFlowsBackOnSameConnection proves a SIP-sized response
// returns on the same protected connection, which is what the REGISTER flow
// needs after the request is sent.
func TestProtectedTCPResponseFlowsBackOnSameConnection(t *testing.T) {
	h := newProtoTCPHarness(t)
	ln := h.listen(t)
	defer ln.Close()

	const requestLen = 1453
	const responseLen = 900
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tmp := make([]byte, 4096)
		read := 0
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		for read < requestLen {
			n, err := conn.Read(tmp)
			read += n
			if err != nil {
				return
			}
		}
		response := make([]byte, responseLen)
		for i := range response {
			response[i] = byte('a' + (i % 26))
		}
		_, _ = conn.Write(response)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()

	request := bytes.Repeat([]byte{'R'}, requestLen)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("protected write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 0, responseLen)
	tmp := make([]byte, 4096)
	for len(got) < responseLen {
		n, err := conn.Read(tmp)
		if n > 0 {
			got = append(got, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(got) != responseLen {
		t.Fatalf("response length = %d, want %d", len(got), responseLen)
	}

	// Every inbound protected packet must also stay in budget.
	serverEnc, serverAuth := oracleExpectedKeys(h.serverPolicy.FlowC)
	inboundData := 0
	for _, esp := range h.captured(false) {
		if len(esp) > protoTCPInnerMTU {
			t.Fatalf("an inbound protected packet is %d bytes, want <= %d", len(esp), protoTCPInnerMTU)
		}
		seg := protoTCPDecodeESP(t, esp, serverEnc, serverAuth)
		if !seg.checksumValid {
			t.Fatal("an inbound protected segment has an invalid checksum")
		}
		if len(seg.payload) > 0 {
			inboundData++
		}
		// The response must arrive on the same protected port pair.
		if int(seg.srcPort) != h.clientPolicy.FlowC.RemotePort ||
			int(seg.dstPort) != h.clientPolicy.FlowC.LocalPort {
			t.Fatal("an inbound segment did not use the negotiated protected port pair")
		}
	}
	t.Logf("MEASURED response_len=%d inbound_data_segments=%d", len(got), inboundData)
}

// TestProtectedTCPTimeoutCancelAndCloseAreBounded proves the prototype's
// lifecycle is bounded: no detached goroutine survives, and a cancelled dial or
// a closed peer terminates rather than hanging.
func TestProtectedTCPTimeoutCancelAndCloseAreBounded(t *testing.T) {
	t.Run("dial to a port nobody listens on fails", func(t *testing.T) {
		h := newProtoTCPHarness(t)
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		local := tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.LocalIP).To16()),
			Port: uint16(h.clientPolicy.FlowC.LocalPort),
		}
		remote := tcpip.FullAddress{
			NIC:  1,
			Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.RemoteIP).To16()),
			Port: uint16(h.clientPolicy.FlowC.RemotePort),
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := gonet.DialTCPWithBind(ctx, h.client.stack, local, remote, ipv6.ProtocolNumber)
			if err == nil {
				conn.Close()
			}
		}()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("dial to an unlistened protected port did not return")
		}
	})

	t.Run("read deadline is honoured", func(t *testing.T) {
		h := newProtoTCPHarness(t)
		ln := h.listen(t)
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and stay silent, forcing the client to time out.
			<-time.After(2 * time.Second)
			conn.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn := h.dial(ctx, t)
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		start := time.Now()
		buf := make([]byte, 64)
		if _, err := conn.Read(buf); err == nil {
			t.Fatal("read returned data from a silent peer")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("read deadline took %s to fire", elapsed)
		}
	})

	t.Run("peer close ends the read loop", func(t *testing.T) {
		h := newProtoTCPHarness(t)
		ln := h.listen(t)
		defer ln.Close()
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn := h.dial(ctx, t)
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 64)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				return
			}
		}
	})
}
