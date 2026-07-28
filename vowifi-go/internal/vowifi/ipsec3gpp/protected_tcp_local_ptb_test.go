package ipsec3gpp

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// NEGATIVE PROOF, retained deliberately and deliberately minimal.
//
// A local ICMPv6 Packet Too Big looked like a way to lower this flow's send
// budget to the ESP transform's limit without touching the link MTU. It is not,
// and this file exists so that conclusion cannot be quietly re-litigated.
//
// gVisor reuses ipv6.calculateNetworkMTU for BOTH the link MTU check and the
// MTU field of an incoming PTB (ipv6/icmp.go, ICMPv6PacketTooBig branch). That
// function rejects anything below header.IPv6MinimumMTU, and the caller folds
// the error to zero:
//
//	networkMTU, err := calculateNetworkMTU(h.MTU(), IPv6MinimumSize)
//	if err != nil { networkMTU = 0 }
//
// so a PTB carrying the ESP budget arrives at TCP as MTU 0:
//
//	tcp/endpoint.go handlePacketTooBig: if v < SndMTU { SndMTU = v }   // 0
//	tcp/snd.go      updateMaxPayloadSize: m = 0 - 20 - maxOptionSize()
//	                                     if m <= 0 { m = 1 }
//
// The send budget collapses to ONE byte per segment, and SndMTU only ever
// ratchets downward, so the flow never recovers. A PTB at the legal 1280 floor
// is the opposite failure: m is larger than the current MaxPayloadSize, so
// updateMaxPayloadSize returns early and nothing changes at all.
//
// The reusable PTB-injection harness this file used to carry has been removed:
// the route is closed, and a general-purpose "inject a local PTB" seam is a
// liability, not an asset. What remains is one inline construction inside one
// test. Nothing here is reachable from production code.
//
// The PTB is delivered to the local stack only. It is never protected, never
// handed to TransformOutbound, and never written to any connection. The quoted
// bytes it carries are synthetic and are never logged.
//
// Assertions and logs are lengths and counts only. No SIP text, key, IV,
// ciphertext, address or identity is printed.

const (
	ptbICMPv6ProtocolNumber = 58
	ptbICMPv6PacketTooBig   = 2
)

// drainProtoTCPPeer is a deterministic barrier: it returns once the synthetic
// peer has actually received want bytes, which means every segment carrying them
// has already traversed the relay and been captured. Reading the capture slice
// without this raced against the relay goroutine and produced an empty baseline
// when the package's tests ran together.
//
// No sleep is used, and the drained bytes are discarded rather than logged.
func drainProtoTCPPeer(t *testing.T, peer net.Conn, want int) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("peer read deadline: %v", err)
	}
	buf := make([]byte, 4096)
	for read := 0; read < want; {
		n, err := peer.Read(buf)
		read += n
		if err != nil {
			t.Fatalf("peer received %d of %d bytes before %v", read, want, err)
		}
	}
}

// ptbICMPv6Checksum computes the RFC 4443 checksum over the IPv6 pseudo-header
// and the ICMPv6 message, by hand.
func ptbICMPv6Checksum(src, dst net.IP, message []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src.To16())
	add(dst.To16())
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(message)))
	add(lenBuf[:])
	add([]byte{0, 0, 0, ptbICMPv6ProtocolNumber})
	add(message)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TestLocalICMPv6PTBBelowIPv6MinimumCollapsesSendBudget is the whole negative
// proof: a PTB expressing the ESP budget does not lower the send budget to that
// budget, it lowers it to one byte.
func TestLocalICMPv6PTBBelowIPv6MinimumCollapsesSendBudget(t *testing.T) {
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
		t.Fatal("synthetic peer never accepted the protected connection")
	}
	defer peer.Close()

	// Baseline: what this flow sends before any PTB.
	//
	// The barrier is the PEER having the bytes, not a sleep: a write returns as
	// soon as the data is queued, so reading the capture immediately would race
	// the relay goroutine.
	if _, err := conn.Write(make([]byte, 600)); err != nil {
		t.Fatalf("baseline write: %v", err)
	}
	drainProtoTCPPeer(t, peer, 600)
	baselineMax := 0
	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	for _, esp := range h.captured(true) {
		seg := protoTCPDecodeESP(t, esp, encKey, authKey)
		if n := len(seg.payload); n > baselineMax {
			baselineMax = n
		}
	}
	if baselineMax == 0 {
		t.Fatal("baseline produced no data segment")
	}
	before := len(h.captured(true))

	// Inject ONE PTB whose MTU expresses the ESP budget. Local stack only.
	local := net.IP(h.clientPolicy.LocalIP)
	remote := net.IP(h.clientPolicy.RemoteIP)

	// The quoted packet must look like traffic we originated, otherwise
	// ipv6.handleControl drops it via checkLocalAddress.
	quoted := make([]byte, protoTCPIPv6Hdr+protoTCPMinHdrLen)
	quoted[0] = 0x60
	binary.BigEndian.PutUint16(quoted[4:6], protoTCPMinHdrLen)
	quoted[6] = ipProtoTCP
	quoted[7] = 64
	copy(quoted[8:24], local.To16())
	copy(quoted[24:40], remote.To16())
	tcpHdr := quoted[protoTCPIPv6Hdr:]
	binary.BigEndian.PutUint16(tcpHdr[0:2], uint16(h.clientPolicy.FlowC.LocalPort))
	binary.BigEndian.PutUint16(tcpHdr[2:4], uint16(h.clientPolicy.FlowC.RemotePort))
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x10 // ACK

	icmp := make([]byte, 8+len(quoted))
	icmp[0] = ptbICMPv6PacketTooBig
	binary.BigEndian.PutUint32(icmp[4:8], uint32(maxProtectedTCPSegmentLen()+protoTCPIPv6Hdr))
	copy(icmp[8:], quoted)
	binary.BigEndian.PutUint16(icmp[2:4], ptbICMPv6Checksum(remote, local, icmp))

	ptb := make([]byte, protoTCPIPv6Hdr+len(icmp))
	ptb[0] = 0x60
	binary.BigEndian.PutUint16(ptb[4:6], uint16(len(icmp)))
	ptb[6] = ptbICMPv6ProtocolNumber
	ptb[7] = 64
	copy(ptb[8:24], remote.To16())
	copy(ptb[24:40], local.To16())
	copy(ptb[protoTCPIPv6Hdr:], icmp)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(ptb),
	})
	h.client.linkEP.InjectInbound(ipv6.ProtocolNumber, pkt)
	pkt.DecRef()

	// Now send again and measure what the sender does. Same barrier as above.
	if _, err := conn.Write(make([]byte, 600)); err != nil {
		t.Fatalf("post-PTB write: %v", err)
	}
	drainProtoTCPPeer(t, peer, 600)
	afterMax, afterMin, afterSegs := 0, 1<<30, 0
	for _, esp := range h.captured(true)[before:] {
		seg := protoTCPDecodeESP(t, esp, encKey, authKey)
		if n := len(seg.payload); n > 0 {
			afterSegs++
			if n > afterMax {
				afterMax = n
			}
			if n < afterMin {
				afterMin = n
			}
		}
	}
	if afterMin == 1<<30 {
		afterMin = 0
	}
	t.Logf("MEASURED ptb_mtu_field=%d ipv6_min_mtu=%d baseline_max_payload=%d",
		maxProtectedTCPSegmentLen()+protoTCPIPv6Hdr, gVisorMinIPv6LinkMTU, baselineMax)
	t.Logf("MEASURED post_ptb_segments=%d post_ptb_max_payload=%d post_ptb_min_payload=%d",
		afterSegs, afterMax, afterMin)

	if afterSegs == 0 {
		t.Fatal("no data segment was emitted after the PTB")
	}
	// The claim: it does NOT settle at the ESP budget.
	safePayload := maxProtectedTCPSegmentLen() - protoTCPMinHdrLen
	if afterMax == safePayload {
		t.Fatalf("post-PTB payload settled at the ESP budget %d; the degenerate behaviour this test documents is gone",
			safePayload)
	}
	if afterMax != 1 {
		t.Fatalf("post-PTB max payload = %d, want 1 (folded MTU 0 -> m<=0 -> m=1)", afterMax)
	}
	t.Logf("VERDICT sub_1280_ptb_usable=false collapses_to_one_byte=true")
}

// TestProtectedTCPMTUDiscoverOptionDoesNotGateTheICMPv6PTBPath records the Gate
// 6.4 finding and closes it: the option is settable but does not participate in
// the ICMPv6 PTB path at all. In this gVisor version e.pmtud is read in exactly
// one place, to decide the IPv4 DF bit.
func TestProtectedTCPMTUDiscoverOptionDoesNotGateTheICMPv6PTBPath(t *testing.T) {
	h := newProtoTCPHarness(t)

	var wq waiter.Queue
	ep, tcpErr := h.client.stack.NewEndpoint(gtcp.ProtocolNumber, protoTCPNetProto, &wq)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint: %s", tcpErr)
	}
	defer ep.Close()

	settable := true
	for _, v := range []tcpip.PMTUDStrategy{
		tcpip.PMTUDiscoveryDont, tcpip.PMTUDiscoveryWant, tcpip.PMTUDiscoveryDo,
	} {
		if err := ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(v)); err != nil {
			settable = false
		}
	}
	// Probe mode is explicitly unsupported here.
	probeSupported := ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryProbe)) == nil

	t.Logf("MEASURED mtu_discover_settable=%v probe_supported=%v gates_icmpv6_ptb=false",
		settable, probeSupported)
	if !settable {
		t.Fatal("MTUDiscoverOption was expected to be settable for Dont/Want/Do")
	}
	if probeSupported {
		t.Fatal("PMTUDiscoveryProbe was expected to be unsupported in this gVisor version")
	}
}
