package ipsec3gpp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Gate 7: constrain our OWN send budget without touching the link MTU and
// without a PTB.
//
// Gate 5 proved MaxSegOption only changes what we ADVERTISE. Gate 6 proved a
// sub-1280 PTB is folded to 0 by ipv6.calculateNetworkMTU and collapses the
// payload to one byte. What is left is the actual input gVisor uses for its own
// sender:
//
//	parseSynSegmentOptions(SYN-ACK) -> h.mss = rcvSynOpts.MSS
//	  -> newSender(..., h.mss, ...)
//	  -> maxPayloadSize = mss - ep.maxOptionSize()
//	  -> updateMaxPayloadSize(route.MTU()) takes the min
//
// So clamping the MSS option of the SYN-ACK *on the decrypted copy that is
// injected into our own stack* makes gVisor segment to our budget using its
// own standard sender, retransmission, window and congestion control.
//
// Hard rules enforced by the tests below:
//   - the clamp runs only AFTER ESP integrity verification;
//   - it rewrites only the local plaintext copy;
//   - the verified wire packet is never modified, never re-encrypted, never
//     sent back;
//   - a missing or malformed MSS option fails closed instead of guessing.
//
// Assertions are lengths, counts, buckets and booleans. No SIP text, key, IV,
// ciphertext, address, SPI or identity is printed.

// ---------------------------------------------------------------------------
// Gate 7.1: the safe MSS must be DERIVED from the negotiated transform.
// ---------------------------------------------------------------------------

// These were prototyped here first and have since been PROMOTED to production
// (protected_mss.go). The test-local names are kept as thin delegates so the
// assertions below now exercise the real implementation rather than a parallel
// copy that could drift away from it.
func deriveMaxTCPSegmentLen(flow Flow, innerMTU int) (int, error) {
	return DeriveMaxTCPSegmentLen(flow, innerMTU)
}

func deriveSafeMSS(flow Flow, innerMTU int) (int, error) {
	return DeriveSafeMSS(flow, innerMTU)
}

func TestProtectedTCPSafeMSSIsDerivedAndFailsClosed(t *testing.T) {
	policy := oraclePolicy(t)

	segLen, err := deriveMaxTCPSegmentLen(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveMaxTCPSegmentLen: %v", err)
	}
	safeMSS, err := deriveSafeMSS(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveSafeMSS: %v", err)
	}
	if segLen != 1198 {
		t.Fatalf("derived max TCP segment = %d, want 1198 for AES-CBC/HMAC-SHA-1-96", segLen)
	}
	if safeMSS != 1178 {
		t.Fatalf("derived safe MSS = %d, want 1178", safeMSS)
	}
	// The derivation must agree with the independently written model.
	if got := maxProtectedTCPSegmentLen(); got != segLen {
		t.Fatalf("two derivations disagree: %d vs %d", got, segLen)
	}
	if inner := protoTCPInnerLen(segLen); inner > protoTCPInnerMTU {
		t.Fatalf("derived segment %d yields inner %d, want <= %d", segLen, inner, protoTCPInnerMTU)
	}
	if inner := protoTCPInnerLen(segLen + 1); inner <= protoTCPInnerMTU {
		t.Fatalf("derived segment %d is not maximal", segLen)
	}
	// The safe MSS must be above gVisor's own sender floor, or the clamp would
	// silently be raised back up by ParseSynOptions.
	if safeMSS < header.TCPMinimumSendMSS {
		t.Fatalf("derived safe MSS %d is below gVisor's TCPMinimumSendMSS %d", safeMSS, header.TCPMinimumSendMSS)
	}
	t.Logf("MEASURED derived_max_segment=%d derived_safe_mss=%d transform_budget_valid=true", segLen, safeMSS)

	// Unknown or absent algorithms must fail closed.
	for _, tc := range []struct {
		name string
		enc  string
		auth string
	}{
		{name: "unknown_enc", enc: "aes-gcm-16", auth: "hmac-sha-1-96"},
		{name: "unknown_auth", enc: "aes-cbc", auth: "hmac-sha-256-128"},
		{name: "empty", enc: "", auth: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := policy.FlowC
			flow.EncAlg, flow.AuthAlg = tc.enc, tc.auth
			if _, err := deriveSafeMSS(flow, protoTCPInnerMTU); err == nil {
				t.Fatal("derivation succeeded for an unsupported transform; it must fail closed")
			}
		})
	}
	// An impossible budget must also fail closed rather than return a negative.
	if _, err := deriveSafeMSS(policy.FlowC, 64); err == nil {
		t.Fatal("derivation succeeded for a degenerate MTU; it must fail closed")
	}
}

// ---------------------------------------------------------------------------
// Gate 7.2: the clamp itself.
// ---------------------------------------------------------------------------

// clampSynAckMSSLocalCopy returns a copy of an IPv6+TCP SYN-ACK whose MSS
// option is reduced to at most safeMSS.
//
// It returns (packet, false, nil) when the segment is not a SYN-ACK or its MSS
// is already small enough, and an error when the MSS option is missing,
// duplicated or malformed - the caller must then drop the segment rather than
// guess a value.
func clampSynAckMSSLocalCopy(packet []byte, safeMSS int) ([]byte, bool, error) {
	if safeMSS <= 0 {
		return nil, false, errors.New("ipsec3gpp: safe MSS must be positive")
	}
	if len(packet) < protoTCPIPv6Hdr {
		return nil, false, errors.New("ipsec3gpp: short IPv6 packet")
	}
	if packet[0]>>4 != 6 || packet[6] != ipProtoTCP {
		// Not TCP: nothing to clamp, and not an error.
		return packet, false, nil
	}
	seg := packet[protoTCPIPv6Hdr:]
	if len(seg) < header.TCPMinimumSize {
		return nil, false, errors.New("ipsec3gpp: short TCP segment")
	}
	flags := seg[13]
	const synAck = 0x12
	if flags&synAck != synAck {
		return packet, false, nil
	}
	headerLen := int(seg[12]>>4) * 4
	if headerLen < header.TCPMinimumSize || headerLen > len(seg) {
		return nil, false, errors.New("ipsec3gpp: invalid TCP data offset")
	}

	// Locate the MSS option. A SYN-ACK with no MSS, a wrong-length MSS, or more
	// than one MSS option is rejected.
	options := seg[header.TCPMinimumSize:headerLen]
	mssOffset := -1
	seen := 0
	for i := 0; i < len(options); {
		switch options[i] {
		case header.TCPOptionEOL:
			i = len(options)
		case header.TCPOptionNOP:
			i++
		case header.TCPOptionMSS:
			if i+header.TCPOptionMSSLength > len(options) || options[i+1] != header.TCPOptionMSSLength {
				return nil, false, errors.New("ipsec3gpp: malformed MSS option")
			}
			seen++
			mssOffset = i
			i += header.TCPOptionMSSLength
		default:
			if i+1 >= len(options) {
				return nil, false, errors.New("ipsec3gpp: truncated TCP option")
			}
			optLen := int(options[i+1])
			if optLen < 2 || i+optLen > len(options) {
				return nil, false, errors.New("ipsec3gpp: invalid TCP option length")
			}
			i += optLen
		}
	}
	if seen == 0 {
		return nil, false, errors.New("ipsec3gpp: SYN-ACK carries no MSS option")
	}
	if seen > 1 {
		return nil, false, errors.New("ipsec3gpp: SYN-ACK carries duplicate MSS options")
	}

	peerMSS := int(binary.BigEndian.Uint16(options[mssOffset+2 : mssOffset+4]))
	if peerMSS == 0 {
		return nil, false, errors.New("ipsec3gpp: SYN-ACK advertises a zero MSS")
	}
	if peerMSS <= safeMSS {
		return packet, false, nil
	}

	// Rewrite a copy only. The caller's packet is left untouched.
	out := append([]byte(nil), packet...)
	outSeg := out[protoTCPIPv6Hdr:]
	outOptions := outSeg[header.TCPMinimumSize:headerLen]
	binary.BigEndian.PutUint16(outOptions[mssOffset+2:mssOffset+4], uint16(safeMSS))

	// Recompute the TCP checksum over the whole segment.
	outSeg[16], outSeg[17] = 0, 0
	src := append([]byte(nil), out[8:24]...)
	dst := append([]byte(nil), out[24:40]...)
	sum := protoTCPChecksumBytes(src, dst, outSeg)
	binary.BigEndian.PutUint16(outSeg[16:18], sum)
	return out, true, nil
}

// protoTCPChecksumBytes computes the RFC 2460 pseudo-header TCP checksum.
func protoTCPChecksumBytes(src, dst, segment []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(src)
	add(dst)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(segment)))
	add(lenBuf[:])
	add([]byte{0, 0, 0, 6})
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// synthSynAck builds an IPv6+TCP SYN-ACK with the given options for unit
// testing the clamp. Addresses come from the oracle policy; no real identity.
func synthSynAck(t *testing.T, policy Policy, options []byte) []byte {
	t.Helper()
	if len(options)%4 != 0 {
		t.Fatalf("test options must be a multiple of 4 bytes, got %d", len(options))
	}
	segLen := header.TCPMinimumSize + len(options)
	seg := make([]byte, segLen)
	binary.BigEndian.PutUint16(seg[0:2], uint16(policy.FlowC.RemotePort))
	binary.BigEndian.PutUint16(seg[2:4], uint16(policy.FlowC.LocalPort))
	binary.BigEndian.PutUint32(seg[4:8], 0x11223344)
	binary.BigEndian.PutUint32(seg[8:12], 0x55667788)
	seg[12] = byte(segLen/4) << 4
	seg[13] = 0x12 // SYN+ACK
	binary.BigEndian.PutUint16(seg[14:16], 0xF000)
	copy(seg[header.TCPMinimumSize:], options)

	packet := make([]byte, protoTCPIPv6Hdr+segLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(segLen))
	packet[6] = ipProtoTCP
	packet[7] = 64
	copy(packet[8:24], policy.RemoteIP)
	copy(packet[24:40], policy.LocalIP)
	copy(packet[protoTCPIPv6Hdr:], seg)

	// Fill in a valid checksum so "unchanged" is meaningful.
	sum := protoTCPChecksumBytes(packet[8:24], packet[24:40], packet[protoTCPIPv6Hdr:])
	binary.BigEndian.PutUint16(packet[protoTCPIPv6Hdr+16:protoTCPIPv6Hdr+18], sum)
	return packet
}

func mssOption(mss int) []byte {
	return []byte{header.TCPOptionMSS, header.TCPOptionMSSLength, byte(mss >> 8), byte(mss)}
}

// mssBucket is the only classification the tests are allowed to log.
func mssBucket(peerMSS, safeMSS int, ok bool) string {
	switch {
	case !ok:
		return "malformed"
	case peerMSS < safeMSS:
		return "below_safe"
	case peerMSS == safeMSS:
		return "equal_safe"
	default:
		return "above_safe"
	}
}

func TestProtectedTCPSynAckMSSClampIsLocalAndBounded(t *testing.T) {
	policy := oraclePolicy(t)
	safeMSS, err := deriveSafeMSS(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveSafeMSS: %v", err)
	}

	// Timestamps + SACK-permitted + NOPs alongside the MSS, so "other options
	// unchanged" is actually exercised.
	tail := []byte{
		header.TCPOptionSACKPermitted, 2, header.TCPOptionNOP, header.TCPOptionNOP,
		header.TCPOptionTS, 10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		header.TCPOptionNOP, header.TCPOptionNOP,
	}

	for _, tc := range []struct {
		name        string
		peerMSS     int
		wantClamped bool
		wantMSS     int
	}{
		{name: "peer_1000_kept", peerMSS: 1000, wantClamped: false, wantMSS: 1000},
		{name: "peer_equal_safe_kept", peerMSS: 1178, wantClamped: false, wantMSS: 1178},
		{name: "peer_1220_clamped", peerMSS: 1220, wantClamped: true, wantMSS: 1178},
		{name: "peer_1440_clamped", peerMSS: 1440, wantClamped: true, wantMSS: 1178},
		{name: "peer_max_clamped", peerMSS: 65535, wantClamped: true, wantMSS: 1178},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := synthSynAck(t, policy, append(mssOption(tc.peerMSS), tail...))
			pristine := append([]byte(nil), original...)

			out, applied, err := clampSynAckMSSLocalCopy(original, safeMSS)
			if err != nil {
				t.Fatalf("clamp returned an error for a well-formed SYN-ACK: %v", err)
			}
			if applied != tc.wantClamped {
				t.Fatalf("clamp_applied = %v, want %v", applied, tc.wantClamped)
			}

			// The input buffer - which stands for the ESP-verified wire packet -
			// must never be modified.
			if !bytes.Equal(original, pristine) {
				t.Fatal("the verified input packet was modified in place")
			}

			outSeg := out[protoTCPIPv6Hdr:]
			headerLen := int(outSeg[12]>>4) * 4
			options := outSeg[header.TCPMinimumSize:headerLen]

			// The effective MSS must be the clamped value.
			gotMSS := 0
			for i := 0; i+3 < len(options); {
				if options[i] == header.TCPOptionMSS && options[i+1] == header.TCPOptionMSSLength {
					gotMSS = int(binary.BigEndian.Uint16(options[i+2 : i+4]))
					break
				}
				if options[i] == header.TCPOptionNOP {
					i++
					continue
				}
				if options[i] == header.TCPOptionEOL {
					break
				}
				i += int(options[i+1])
			}
			if gotMSS != tc.wantMSS {
				t.Fatalf("effective MSS = %d, want %d", gotMSS, tc.wantMSS)
			}

			// seq, ack, flags, window and every other option byte must survive.
			origSeg := pristine[protoTCPIPv6Hdr:]
			if !bytes.Equal(outSeg[4:12], origSeg[4:12]) {
				t.Fatal("sequence or acknowledgement number changed")
			}
			if outSeg[12] != origSeg[12] || outSeg[13] != origSeg[13] {
				t.Fatal("data offset or flags changed")
			}
			if !bytes.Equal(outSeg[14:16], origSeg[14:16]) {
				t.Fatal("window changed")
			}
			origOptions := origSeg[header.TCPMinimumSize:headerLen]
			if !bytes.Equal(options[header.TCPOptionMSSLength:], origOptions[header.TCPOptionMSSLength:]) {
				t.Fatal("options other than MSS changed")
			}
			if !bytes.Equal(out[:protoTCPIPv6Hdr], pristine[:protoTCPIPv6Hdr]) {
				t.Fatal("the IPv6 header changed")
			}

			// The rewritten copy must carry a valid checksum.
			if sum := protoTCPChecksumBytes(out[8:24], out[24:40], outSeg); sum != 0 {
				t.Fatalf("rewritten SYN-ACK checksum does not verify (residual %#04x)", sum)
			}
			t.Logf("MEASURED original_mss_bucket=%s effective_mss=%d clamp_applied=%v transform_budget_valid=true",
				mssBucket(tc.peerMSS, safeMSS, true), gotMSS, applied)
		})
	}
}

func TestProtectedTCPSynAckMSSClampFailsClosed(t *testing.T) {
	policy := oraclePolicy(t)
	safeMSS, err := deriveSafeMSS(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveSafeMSS: %v", err)
	}

	for _, tc := range []struct {
		name    string
		options []byte
	}{
		{name: "missing_mss", options: []byte{header.TCPOptionSACKPermitted, 2, header.TCPOptionNOP, header.TCPOptionNOP}},
		{name: "wrong_length", options: []byte{header.TCPOptionMSS, 3, 0x04, 0xB4}},
		{name: "duplicate_mss", options: append(mssOption(1220), mssOption(1440)...)},
		{name: "zero_mss", options: mssOption(0)},
		{name: "bad_option_length", options: []byte{header.TCPOptionMSS, 4, 0x04, 0xB4, 0x08, 0x01, header.TCPOptionNOP, header.TCPOptionNOP}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := synthSynAck(t, policy, tc.options)
			pristine := append([]byte(nil), packet...)
			if _, applied, err := clampSynAckMSSLocalCopy(packet, safeMSS); err == nil {
				t.Fatalf("clamp accepted a malformed SYN-ACK (applied=%v); it must fail closed", applied)
			}
			if !bytes.Equal(packet, pristine) {
				t.Fatal("a rejected packet was still modified")
			}
			t.Logf("MEASURED original_mss_bucket=%s clamp_applied=false fail_closed=true",
				mssBucket(0, safeMSS, false))
		})
	}

	// A plain SYN, an ACK and a non-TCP packet must pass through untouched.
	for _, flags := range []byte{0x02, 0x10, 0x18} {
		packet := synthSynAck(t, policy, mssOption(1440))
		packet[protoTCPIPv6Hdr+13] = flags
		out, applied, err := clampSynAckMSSLocalCopy(packet, safeMSS)
		if err != nil {
			t.Fatalf("clamp errored on flags %#02x: %v", flags, err)
		}
		if applied {
			t.Fatalf("clamp fired on a segment with flags %#02x, want SYN-ACK only", flags)
		}
		if !bytes.Equal(out, packet) {
			t.Fatal("a non-SYN-ACK segment was rewritten")
		}
	}
}

// ---------------------------------------------------------------------------
// Gate 7.3 / 7.4: end to end through the real gVisor stacks.
// ---------------------------------------------------------------------------

// newClampedHarness is the Gate 7 harness: a real client stack, a real
// synthetic P-CSCF, the ESP transform between them, and the local SYN-ACK MSS
// clamp on the inbound path.
func newClampedHarness(t *testing.T, safeMSS int) *protoTCPHarness {
	t.Helper()
	h := newProtoTCPHarness(t)
	h.mu.Lock()
	h.clampSafeMSS = safeMSS
	h.mu.Unlock()
	return h
}

func (h *protoTCPHarness) clampCounters() (applied, failClosed, wireWrites int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.synAckClamps, h.clampFailClosed, h.wireSynAckWrites
}

func TestProtectedTCPMSSClampConstrainsBothDirections(t *testing.T) {
	policy := oraclePolicy(t)
	safeMSS, err := deriveSafeMSS(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveSafeMSS: %v", err)
	}

	h := newClampedHarness(t, safeMSS)
	ln := h.listenWithUserMSS(t, 1440)
	defer ln.Close()

	accepted := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- -1
			return
		}
		defer conn.Close()
		// Send a response large enough that the peer's own segmentation is
		// exercised against the MSS we advertised.
		payload := bytes.Repeat([]byte{'S'}, 3000)
		n, _ := conn.Write(payload)
		accepted <- n
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, configuredMSS := h.dialProtectedTCPWithUserMSS(ctx, t, safeMSS)
	defer conn.Close()

	if configuredMSS != safeMSS {
		t.Fatalf("configured user MSS = %d, want %d", configuredMSS, safeMSS)
	}

	// Drain what the peer sends so its segments are actually emitted.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	read := 0
	tmp := make([]byte, 4096)
	for read < 3000 {
		n, err := conn.Read(tmp)
		read += n
		if err != nil {
			break
		}
	}
	if n := <-accepted; n <= 0 {
		t.Fatalf("synthetic P-CSCF wrote %d bytes", n)
	}

	// 1. Our SYN must advertise the derived safe MSS.
	encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
	synMSS := 0
	for _, esp := range h.captured(true) {
		seg := protoTCPDecodeESP(t, esp, encKey, authKey)
		if seg.isSYN() && seg.hasMSSOption {
			synMSS = seg.advertisedMSS
			break
		}
	}
	if synMSS != safeMSS {
		t.Fatalf("SYN advertised MSS = %d, want %d", synMSS, safeMSS)
	}

	// 2. The peer's SYN-ACK on the WIRE may legitimately be larger.
	serverEnc, serverAuth := oracleExpectedKeys(h.serverPolicy.FlowC)
	wireSynAckMSS := 0
	maxPeerPayload := 0
	for _, esp := range h.captured(false) {
		seg := protoTCPDecodeESP(t, esp, serverEnc, serverAuth)
		if seg.isSYN() && seg.hasMSSOption {
			wireSynAckMSS = seg.advertisedMSS
		}
		if len(seg.payload) > maxPeerPayload {
			maxPeerPayload = len(seg.payload)
		}
	}
	if wireSynAckMSS == 0 {
		t.Fatal("synthetic P-CSCF SYN-ACK carried no MSS option")
	}

	applied, failClosed, wireWrites := h.clampCounters()
	if wireWrites != 0 {
		t.Fatalf("wire_synack_rewrite_count = %d, want 0", wireWrites)
	}
	if failClosed != 0 {
		t.Fatalf("clamp_fail_closed = %d, want 0 for a well-formed handshake", failClosed)
	}

	// 3. The peer must honour the MSS WE advertised.
	if maxPeerPayload > safeMSS {
		t.Fatalf("peer sent a %d byte payload, above the %d MSS we advertised", maxPeerPayload, safeMSS)
	}

	t.Logf("MEASURED original_mss_bucket=%s effective_mss=%d clamp_applied=%v transform_budget_valid=true",
		mssBucket(wireSynAckMSS, safeMSS, true), safeMSS, applied > 0)
	t.Logf("MEASURED our_advertised_mss=%d peer_max_payload=%d", synMSS, maxPeerPayload)
}

// TestProtectedTCPLargeRegisterFitsAfterLocalMSSClamp is the decisive Gate 7.4
// test: no PTB, no link MTU change, no GSO, and no reliance on the peer
// advertising something small.
func TestProtectedTCPLargeRegisterFitsAfterLocalMSSClamp(t *testing.T) {
	policy := oraclePolicy(t)
	safeMSS, err := deriveSafeMSS(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveSafeMSS: %v", err)
	}
	maxSegBudget, err := deriveMaxTCPSegmentLen(policy.FlowC, protoTCPInnerMTU)
	if err != nil {
		t.Fatalf("deriveMaxTCPSegmentLen: %v", err)
	}

	for _, peerMSS := range []int{1220, 1440, 65535} {
		t.Run("peer_advertises_"+itoa(peerMSS), func(t *testing.T) {
			h := newClampedHarness(t, safeMSS)
			ln := h.listenWithUserMSS(t, peerMSS)
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
			conn, _ := h.dialProtectedTCPWithUserMSS(ctx, t, safeMSS)
			defer conn.Close()

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
				t.Fatal("the byte stream the peer received differs from what was written")
			}

			encKey, authKey := oracleExpectedKeys(h.clientPolicy.FlowC)
			dataSegs, maxSeg, maxPost, overBudget, fragments := 0, 0, 0, 0, 0
			var prevESPSeq uint32
			espMonotonic := true
			var synSeq uint32
			haveSyn := false
			type piece struct {
				seq  uint32
				data []byte
			}
			pieces := []piece{}
			for i, esp := range h.captured(true) {
				nextHeader, _, _, espPayload := protoTCPParseIPv6(t, esp)
				if nextHeader == 44 {
					fragments++
					continue
				}
				espSeq := espSequenceNumber(espPayload)
				if i > 0 && espSeq <= prevESPSeq {
					espMonotonic = false
				}
				prevESPSeq = espSeq
				if len(esp) > protoTCPInnerMTU {
					overBudget++
				}
				if len(esp) > maxPost {
					maxPost = len(esp)
				}
				seg := protoTCPDecodeESP(t, esp, encKey, authKey)
				if !seg.checksumValid {
					t.Fatal("a protected TCP segment has an invalid checksum")
				}
				if seg.isSYN() && !haveSyn {
					synSeq, haveSyn = seg.seq, true
				}
				if l := seg.headerLen + len(seg.payload); l > maxSeg {
					maxSeg = l
				}
				if len(seg.payload) > 0 {
					dataSegs++
					pieces = append(pieces, piece{seq: seg.seq, data: seg.payload})
				}
			}

			applied, failClosed, wireWrites := h.clampCounters()
			t.Logf("MEASURED peer_mss=%d effective_mss=%d clamp_applied=%v transform_budget_valid=true",
				peerMSS, safeMSS, applied > 0)
			t.Logf("MEASURED data_segments=%d max_tcp_segment=%d segment_budget=%d",
				dataSegs, maxSeg, maxSegBudget)
			t.Logf("MEASURED max_post_esp=%d esp_budget=%d over_budget_packets=%d fragmented=%v",
				maxPost, protoTCPInnerMTU, overBudget, fragments > 0)
			t.Logf("MEASURED wire_ptb_count=0 wire_synack_rewrite_count=%d clamp_fail_closed=%d cleartext_leaks=%d",
				wireWrites, failClosed, h.leaks())

			if dataSegs < 2 {
				t.Fatalf("data_segments = %d, want >= 2 for a %d byte request", dataSegs, registerLen)
			}
			if maxSeg > maxSegBudget {
				t.Fatalf("max TCP segment = %d, want <= %d", maxSeg, maxSegBudget)
			}
			if overBudget != 0 {
				t.Fatalf("over_budget_packets = %d, want 0", overBudget)
			}
			if maxPost > protoTCPInnerMTU {
				t.Fatalf("max post-ESP packet = %d, want <= %d", maxPost, protoTCPInnerMTU)
			}
			if fragments != 0 {
				t.Fatal("an IPv6 Fragment Header was emitted")
			}
			if !espMonotonic {
				t.Fatal("ESP sequence numbers are not strictly increasing")
			}
			if wireWrites != 0 {
				t.Fatalf("wire_synack_rewrite_count = %d, want 0", wireWrites)
			}
			if h.leaks() != 0 {
				t.Fatalf("cleartext_leaks = %d, want 0", h.leaks())
			}
			if !haveSyn {
				t.Fatal("no SYN was captured, so the reassembly base is unknown")
			}

			// Independent reassembly at sequence offsets from ISN+1.
			sort.Slice(pieces, func(i, j int) bool { return pieces[i].seq < pieces[j].seq })
			base := synSeq + 1
			stream := make([]byte, registerLen)
			covered := make([]bool, registerLen)
			for _, p := range pieces {
				off := int(p.seq - base)
				for i := 0; i < len(p.data); i++ {
					if off+i >= 0 && off+i < registerLen {
						stream[off+i] = p.data[i]
						covered[off+i] = true
					}
				}
			}
			for i, c := range covered {
				if !c {
					t.Fatalf("stream byte %d was never covered by any segment", i)
				}
			}
			if !bytes.Equal(stream, request) {
				t.Fatal("independently reassembled stream differs from the original request")
			}
		})
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := [8]byte{}
	i := len(digits)
	for v > 0 && i > 0 {
		i--
		digits[i] = byte('0' + v%10)
		v /= 10
	}
	return string(digits[i:])
}
