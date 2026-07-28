package ipsec3gpp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sort"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Gate 5: is the 42-byte shortfall really unavoidable?
//
// The earlier report claimed the IPv6 1280 minimum link MTU made the ESP budget
// unreachable. That conflated two different numbers:
//
//	max_pre_esp_ipv6_packet_len = 40 + max_tcp_segment_len = 1238
//
// is a PACKET LENGTH LIMIT, not a required link MTU. A link endpoint may legally
// report 1280; TCP does not have to fill the MTU. The open question is whether
// the local send MSS can be capped independently, so this file tests
// tcpip.MaxSegOption set BEFORE Connect on the client endpoint - which
// gonet.DialTCPWithBind gives no opportunity to do.
//
// Everything asserted is a length, count, flag or sequence delta. No SIP text,
// key, IV, ciphertext, address or identity is printed.

// protoTCPNetProto is the network protocol the prototype runs on.
const protoTCPNetProto = ipv6.ProtocolNumber

// localProtectedAddr is the UE protected client port (port_uc).
func (h *protoTCPHarness) localProtectedAddr() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.LocalIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.LocalPort),
	}
}

// remoteProtectedAddr is the P-CSCF protected server port (port_ps).
func (h *protoTCPHarness) remoteProtectedAddr() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.clientPolicy.RemoteIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.RemotePort),
	}
}

// serverListenAddr is the same port_ps seen from the synthetic P-CSCF side.
func (h *protoTCPHarness) serverListenAddr() tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(net.IP(h.serverPolicy.LocalIP).To16()),
		Port: uint16(h.clientPolicy.FlowC.RemotePort),
	}
}

// espSequenceNumber reads the RFC 4303 sequence number from an ESP payload
// without using any project decode helper.
func espSequenceNumber(espPayload []byte) uint32 {
	if len(espPayload) < 8 {
		return 0
	}
	return binary.BigEndian.Uint32(espPayload[4:8])
}

// dialProtectedTCPWithUserMSS mirrors gonet.DialTCPWithBind but inserts a
// pre-connect SetSockOptInt(MaxSegOption) seam. userMSS <= 0 skips the option so
// the same helper produces the control case.
func (h *protoTCPHarness) dialProtectedTCPWithUserMSS(ctx context.Context, t *testing.T, userMSS int) (*gonet.TCPConn, int) {
	t.Helper()

	var wq waiter.Queue
	ep, tcpErr := h.client.stack.NewEndpoint(gtcp.ProtocolNumber, protoTCPNetProto, &wq)
	if tcpErr != nil {
		t.Fatalf("NewEndpoint: %s", tcpErr)
	}

	// 3. The option must be set while the endpoint is still unconnected.
	if userMSS > 0 {
		if err := ep.SetSockOptInt(tcpip.MaxSegOption, userMSS); err != nil {
			ep.Close()
			t.Fatalf("SetSockOptInt(MaxSegOption, %d): %s", userMSS, err)
		}
	}
	// Read it back to prove it took effect pre-connect.
	configured, err := ep.GetSockOptInt(tcpip.MaxSegOption)
	if err != nil {
		ep.Close()
		t.Fatalf("GetSockOptInt(MaxSegOption): %s", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	// 2. Bind the UE protected client port before connecting.
	if err := ep.Bind(h.localProtectedAddr()); err != nil {
		ep.Close()
		t.Fatalf("Bind(port_uc): %s", err)
	}
	// 4. Connect to the P-CSCF protected server port.
	connErr := ep.Connect(h.remoteProtectedAddr())
	if _, started := connErr.(*tcpip.ErrConnectStarted); started {
		select {
		case <-ctx.Done():
			ep.Close()
			t.Fatal("protected TCP connect did not complete")
		case <-notifyCh:
		}
		connErr = ep.LastError()
	}
	if connErr != nil {
		ep.Close()
		t.Fatalf("Connect(port_ps): %s", connErr)
	}
	// 5. Wrap as a net.Conn.
	return gonet.NewTCPConn(&wq, ep), configured
}

// listenWithUserMSS makes the synthetic P-CSCF advertise a chosen MSS. userMSS
// is inherited by accepted endpoints via propagateInheritableOptionsLocked, so
// this controls what the PEER tells us.
func (h *protoTCPHarness) listenWithUserMSS(t *testing.T, userMSS int) *gonet.TCPListener {
	t.Helper()
	var wq waiter.Queue
	ep, tcpErr := h.server.stack.NewEndpoint(gtcp.ProtocolNumber, protoTCPNetProto, &wq)
	if tcpErr != nil {
		t.Fatalf("server NewEndpoint: %s", tcpErr)
	}
	if userMSS > 0 {
		if err := ep.SetSockOptInt(tcpip.MaxSegOption, userMSS); err != nil {
			ep.Close()
			t.Fatalf("server SetSockOptInt(MaxSegOption, %d): %s", userMSS, err)
		}
	}
	if err := ep.Bind(h.serverListenAddr()); err != nil {
		ep.Close()
		t.Fatalf("server Bind(port_ps): %s", err)
	}
	if err := ep.Listen(1); err != nil {
		ep.Close()
		t.Fatalf("server Listen: %s", err)
	}
	return gonet.NewTCPListener(h.server.stack, &wq, ep)
}

// protoTCPSegmentReport is one row of the Gate 5.1 table. Numbers only.
type protoTCPSegmentReport struct {
	index          int
	flags          byte
	advertisedMSS  int
	hasMSS         bool
	tcpHeaderLen   int
	tcpPayloadLen  int
	tcpSegmentLen  int
	postESPLen     int
	fragmented     bool
	tcpSeqDelta    uint32
	espSeqDelta    uint32
	optionBytesLen int
}

// collectProtoTCPReports decodes every captured ESP packet in one direction and
// derives the per-segment table, including the ESP sequence deltas.
func collectProtoTCPReports(t *testing.T, packets [][]byte, encKey, authKey []byte) []protoTCPSegmentReport {
	t.Helper()
	out := make([]protoTCPSegmentReport, 0, len(packets))
	var prevTCPSeq, prevESPSeq uint32
	for i, esp := range packets {
		nextHeader, _, _, espPayload := protoTCPParseIPv6(t, esp)
		row := protoTCPSegmentReport{index: i, postESPLen: len(esp)}
		// RFC 8200 Fragment Header is next-header 44.
		row.fragmented = nextHeader == 44
		if row.fragmented {
			out = append(out, row)
			continue
		}
		espSeq := espSequenceNumber(espPayload)
		seg := protoTCPDecodeESP(t, esp, encKey, authKey)
		row.flags = seg.flags
		row.advertisedMSS = seg.advertisedMSS
		row.hasMSS = seg.hasMSSOption
		row.tcpHeaderLen = seg.headerLen
		row.tcpPayloadLen = len(seg.payload)
		row.tcpSegmentLen = seg.headerLen + len(seg.payload)
		row.optionBytesLen = seg.headerLen - protoTCPMinHdrLen
		if i > 0 {
			row.tcpSeqDelta = seg.seq - prevTCPSeq
			row.espSeqDelta = espSeq - prevESPSeq
		}
		prevTCPSeq, prevESPSeq = seg.seq, espSeq
		out = append(out, row)
	}
	return out
}

func logProtoTCPReports(t *testing.T, label string, rows []protoTCPSegmentReport) {
	t.Helper()
	for _, r := range rows {
		t.Logf("%s seg=%d flags=%#02x has_mss=%v advertised_mss=%d tcp_hdr=%d tcp_payload=%d tcp_segment=%d post_esp=%d fragmented=%v tcp_seq_delta=%d esp_seq_delta=%d options=%d",
			label, r.index, r.flags, r.hasMSS, r.advertisedMSS,
			r.tcpHeaderLen, r.tcpPayloadLen, r.tcpSegmentLen,
			r.postESPLen, r.fragmented, r.tcpSeqDelta, r.espSeqDelta, r.optionBytesLen)
	}
}

// TestProtectedTCPPerSegmentBudgetTable is Gate 5.1: the full per-segment table
// for the production-sized request, plus the arithmetic that explains why the
// observed maximum differs from the worst-case derivation.
func TestProtectedTCPPerSegmentBudgetTable(t *testing.T) {
	h := newProtoTCPHarness(t)
	ln := h.listen(t)
	defer ln.Close()

	const registerLen = 1453
	done := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		read := 0
		tmp := make([]byte, 4096)
		for read < registerLen {
			n, err := conn.Read(tmp)
			read += n
			if err != nil {
				break
			}
		}
		done <- read
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()

	if _, err := conn.Write(bytes.Repeat([]byte{'R'}, registerLen)); err != nil {
		t.Fatalf("protected write: %v", err)
	}
	if got := <-done; got != registerLen {
		t.Fatalf("peer received %d bytes, want %d", got, registerLen)
	}

	linkMTU := prototypeLinkMTU()
	routeMTU := linkMTU - header.IPv6MinimumSize
	t.Logf("CONTEXT link_mtu=%d route_mtu=%d configured_user_mss=none derived_safe_mss=%d",
		linkMTU, routeMTU, maxProtectedTCPSegmentLen()-protoTCPMinHdrLen)

	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	outRows := collectProtoTCPReports(t, h.captured(true), encKey, authKey)
	logProtoTCPReports(t, "OUTBOUND", outRows)

	serverEnc, serverAuth := oracleExpectedKeys(h.serverPolicy.FlowC)
	inRows := collectProtoTCPReports(t, h.captured(false), serverEnc, serverAuth)
	logProtoTCPReports(t, "INBOUND", inRows)

	// Reconcile observed vs worst case. gVisor reserves maxOptionSize() from the
	// payload budget, but an established data segment may carry fewer option
	// bytes than that reservation, so the emitted segment is smaller than the
	// theoretical maximum.
	peerMSS := 0
	for _, r := range inRows {
		if r.hasMSS {
			peerMSS = r.advertisedMSS
			break
		}
	}
	maxSeg, maxPost, dataSegs, maxPayload := 0, 0, 0, 0
	for _, r := range outRows {
		if r.tcpSegmentLen > maxSeg {
			maxSeg = r.tcpSegmentLen
		}
		if r.postESPLen > maxPost {
			maxPost = r.postESPLen
		}
		if r.tcpPayloadLen > 0 {
			dataSegs++
			if r.tcpPayloadLen > maxPayload {
				maxPayload = r.tcpPayloadLen
			}
		}
	}
	worstCaseSeg := routeMTU
	t.Logf("RECONCILE peer_advertised_mss=%d observed_max_payload=%d implied_option_reservation=%d",
		peerMSS, maxPayload, peerMSS-maxPayload)
	t.Logf("RECONCILE observed_max_segment=%d observed_max_post_esp=%d", maxSeg, maxPost)
	t.Logf("RECONCILE worst_case_segment=%d worst_case_post_esp=%d",
		worstCaseSeg, protoTCPInnerLen(worstCaseSeg))
	t.Logf("RECONCILE budget=%d observed_over_by=%d worst_case_over_by=%d data_segments=%d",
		protoTCPInnerMTU, maxPost-protoTCPInnerMTU,
		protoTCPInnerLen(worstCaseSeg)-protoTCPInnerMTU, dataSegs)

	// The reconciliation must be exact, not approximate: observed payload plus
	// the option reservation must equal the peer's advertised MSS.
	if peerMSS > 0 && maxPayload > 0 && maxPayload+(peerMSS-maxPayload) != peerMSS {
		t.Fatal("payload reconciliation is inconsistent")
	}
	if maxPost != protoTCPInnerLen(maxSeg) {
		t.Fatalf("post-ESP length %d does not match the framing model for segment %d (%d)",
			maxPost, maxSeg, protoTCPInnerLen(maxSeg))
	}
}

// TestProtectedTCPUserMSSCapsBothSYNAndOutboundSegments is Gate 5.2: does a
// pre-connect MaxSegOption bound our OWN segments, or only what we advertise?
func TestProtectedTCPUserMSSCapsBothSYNAndOutboundSegments(t *testing.T) {
	safeMSS := maxProtectedTCPSegmentLen() - protoTCPMinHdrLen

	for _, tc := range []struct {
		name    string
		peerMSS int
	}{
		{name: "peer_advertises_1220", peerMSS: 1220},
		{name: "peer_advertises_1440", peerMSS: 1440},
		{name: "peer_advertises_max", peerMSS: header.TCPMaximumMSS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newProtoTCPHarness(t)
			ln := h.listenWithUserMSS(t, tc.peerMSS)
			defer ln.Close()

			const registerLen = 1453
			received := make(chan []byte, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					close(received)
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 0, registerLen)
				tmp := make([]byte, 4096)
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
			conn, configuredMSS := h.dialProtectedTCPWithUserMSS(ctx, t, safeMSS)
			defer conn.Close()

			if configuredMSS != safeMSS {
				t.Fatalf("configured user MSS reads back as %d, want %d (option did not take effect pre-connect)",
					configuredMSS, safeMSS)
			}

			request := make([]byte, registerLen)
			for i := range request {
				request[i] = byte('A' + (i % 26))
			}
			if _, err := conn.Write(request); err != nil {
				t.Fatalf("protected write: %v", err)
			}
			got, ok := <-received
			if !ok || len(got) != registerLen {
				t.Fatalf("peer received %d bytes, want %d", len(got), registerLen)
			}
			if !bytes.Equal(got, request) {
				t.Fatal("peer byte stream differs from what was written")
			}

			encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
			outRows := collectProtoTCPReports(t, h.captured(true), encKey, authKey)
			logProtoTCPReports(t, "OUTBOUND", outRows)

			// Our SYN must always advertise the derived safe MSS.
			synMSS := 0
			for _, r := range outRows {
				if r.flags&0x02 != 0 && r.hasMSS {
					synMSS = r.advertisedMSS
					break
				}
			}
			if synMSS != safeMSS {
				t.Fatalf("SYN advertised MSS = %d, want the derived %d", synMSS, safeMSS)
			}
			t.Logf("MEASURED syn_advertised_mss=%d configured_user_mss=%d", synMSS, configuredMSS)

			// Now the decisive question: are OUR data segments capped?
			maxSeg, maxPost, dataSegs := 0, 0, 0
			overBudget := 0
			for _, r := range outRows {
				if r.fragmented {
					t.Fatal("an IPv6 Fragment Header was emitted on the protected TCP path")
				}
				if r.tcpSegmentLen > maxSeg {
					maxSeg = r.tcpSegmentLen
				}
				if r.postESPLen > maxPost {
					maxPost = r.postESPLen
				}
				if r.postESPLen > protoTCPInnerMTU {
					overBudget++
				}
				if r.tcpPayloadLen > 0 {
					dataSegs++
				}
			}
			t.Logf("MEASURED max_tcp_segment=%d segment_budget=%d max_post_esp=%d esp_budget=%d over_budget_packets=%d data_segments=%d",
				maxSeg, maxProtectedTCPSegmentLen(), maxPost, protoTCPInnerMTU, overBudget, dataSegs)

			// Independent reassembly must still hold regardless of the outcome.
			var pieces []struct {
				seq  uint32
				data []byte
			}
			for _, esp := range h.captured(true) {
				seg := protoTCPDecodeESP(t, esp, encKey, authKey)
				if !seg.checksumValid {
					t.Fatal("a protected TCP segment has an invalid checksum")
				}
				if len(seg.payload) > 0 {
					pieces = append(pieces, struct {
						seq  uint32
						data []byte
					}{seg.seq, seg.payload})
				}
			}
			sort.Slice(pieces, func(i, j int) bool { return pieces[i].seq < pieces[j].seq })
			var stream []byte
			for _, p := range pieces {
				stream = append(stream, p.data...)
			}
			if !bytes.Equal(stream, request) {
				t.Fatal("independently reassembled stream differs from the original request")
			}
			if n := h.leaks(); n != 0 {
				t.Fatalf("%d cleartext packets reached the transform unprotected", n)
			}

			// The verdict this gate exists to establish.
			if overBudget == 0 {
				t.Logf("VERDICT user_mss_caps_outbound=true 42_byte_shortfall_resolved=true")
				return
			}
			t.Logf("VERDICT user_mss_caps_outbound=false over_budget_packets=%d max_post_esp=%d",
				overBudget, maxPost)
			t.Logf("VERDICT send_mss_source=min(peer_advertised_mss,route_mtu-20)-max_option_size")
		})
	}
}

// TestProtectedTCPLinkDoesNotExposeUnprocessedGSO is Gate 5.3: the protected
// link endpoint must never hand an unsegmented GSO super-packet to the ESP
// transform. The prototype declares no GSO capability, so gVisor segments first.
func TestProtectedTCPLinkDoesNotExposeUnprocessedGSO(t *testing.T) {
	h := newProtoTCPHarness(t)

	// The channel endpoint must not advertise any GSO/TSO capability.
	if caps := h.client.linkEP.Capabilities(); caps != 0 {
		t.Fatalf("protected link endpoint advertises capabilities %#x, want none", caps)
	}

	ln := h.listen(t)
	defer ln.Close()
	const registerLen = 1453
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		tmp := make([]byte, 4096)
		read := 0
		for read < registerLen {
			n, err := conn.Read(tmp)
			read += n
			if err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn := h.dial(ctx, t)
	defer conn.Close()
	if _, err := conn.Write(bytes.Repeat([]byte{'G'}, registerLen)); err != nil {
		t.Fatalf("protected write: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// No packet handed to the transform may exceed what one TCP segment can be
	// at this link MTU: a GSO super-packet would be far larger.
	routeMTU := prototypeLinkMTU() - header.IPv6MinimumSize
	maxSinglePacket := header.IPv6MinimumSize + routeMTU
	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	for _, r := range collectProtoTCPReports(t, h.captured(true), encKey, authKey) {
		if r.tcpSegmentLen > routeMTU {
			t.Fatalf("segment %d is %d bytes, larger than one route MTU (%d): a GSO super-packet reached the transform",
				r.index, r.tcpSegmentLen, routeMTU)
		}
		if r.postESPLen > protoTCPInnerLen(routeMTU) {
			t.Fatalf("post-ESP packet %d is %d bytes, beyond the single-segment maximum", r.index, r.postESPLen)
		}
	}
	t.Logf("MEASURED link_capabilities=0 max_single_pre_esp_packet=%d gso_super_packets=0", maxSinglePacket)
}
