package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Gate 3: do NOT assume "TCP avoids IP fragmentation".
//
// TCP avoids fragmentation only when something segments the byte stream to a
// safe size. Inside this project the ESP-protected channel is not a TCP stack:
// buildOutboundTCPPacket synthesises a fixed 20-byte TCP header
// (buildMinimalTCPSegment: seq=1, ack=1, PSH+ACK, no checksum, no options) and
// writeFlow encrypts whatever it is handed as ONE packet. There is no MSS, no
// sequence tracking, and no segmentation anywhere in the path.
//
// These tests derive the real TCP budget from the same ESP framing the outbound
// oracle already validated, and then measure what the existing TCP secure
// channel actually emits for a production-sized REGISTER.
//
// Assertions are lengths, counts and header flags only. No SIP text, key, IV or
// ciphertext is printed.

// ESP framing budget for a TCP inner packet:
//
//	inner = 40(IPv6) + 8(SPI+Seq) + 16(IV) + roundUp16(tcpSegLen + 2) + 12(ICV)
//	      = 76 + roundUp16(tcpSegLen + 2)
//
// tcpSegLen is header+payload, so the padding step is what makes a plain
// subtraction wrong here exactly as it was for UDP.
const (
	tcpOracleInnerMTU      = 1280
	tcpOracleFixedOverhead = 76
	tcpOracleESPTrailer    = 2
	tcpOracleESPBlock      = 16
	tcpOracleMinHeaderLen  = 20
)

func tcpOracleInnerLen(tcpSegLen int) int {
	plain := tcpSegLen + tcpOracleESPTrailer
	blocks := (plain + tcpOracleESPBlock - 1) / tcpOracleESPBlock
	return tcpOracleFixedOverhead + blocks*tcpOracleESPBlock
}

// tcpOracleMaxSegLen is the largest TCP header+payload whose ESP inner packet
// still fits the SWu raw IP MTU. Derived, not hardcoded.
func tcpOracleMaxSegLen() int {
	usable := tcpOracleInnerMTU - tcpOracleFixedOverhead
	usable -= usable % tcpOracleESPBlock
	return usable - tcpOracleESPTrailer
}

// tcpOracleMaxPayloadForHeader is the safe MSS for a given TCP header length.
func tcpOracleMaxPayloadForHeader(headerLen int) int {
	return tcpOracleMaxSegLen() - headerLen
}

// TestProtectedTCPSegmentBudgetIsDerivedNotAssumed pins the budget arithmetic so
// a future MSS implementation cannot silently pick a wrong constant.
func TestProtectedTCPSegmentBudgetIsDerivedNotAssumed(t *testing.T) {
	maxSeg := tcpOracleMaxSegLen()
	if maxSeg != 1198 {
		t.Fatalf("max TCP header+payload = %d, want 1198", maxSeg)
	}
	if got := tcpOracleInnerLen(maxSeg); got > tcpOracleInnerMTU {
		t.Fatalf("inner packet for max segment = %d, want <= %d", got, tcpOracleInnerMTU)
	}
	if got := tcpOracleInnerLen(maxSeg + 1); got <= tcpOracleInnerMTU {
		t.Fatalf("budget %d is not maximal: one more byte still fits at %d", maxSeg, got)
	}

	// The header length actually decides the safe MSS, so both the 20-byte and
	// the 32-byte (timestamps/SACK) cases must be derived, never assumed.
	for _, tc := range []struct{ headerLen, wantPayload int }{
		{headerLen: 20, wantPayload: 1178},
		{headerLen: 32, wantPayload: 1166},
	} {
		got := tcpOracleMaxPayloadForHeader(tc.headerLen)
		if got != tc.wantPayload {
			t.Fatalf("safe payload for %d-byte header = %d, want %d", tc.headerLen, got, tc.wantPayload)
		}
		if inner := tcpOracleInnerLen(tc.headerLen + got); inner > tcpOracleInnerMTU {
			t.Fatalf("inner packet for %d-byte header at payload %d = %d, want <= %d",
				tc.headerLen, got, inner, tcpOracleInnerMTU)
		}
	}
}

// TestProtectedTCPSecureChannelEmitsFixedHeaderWithoutSegmentation is the
// characterization RED: it measures what the existing TCP secure channel does
// with a production-sized protected REGISTER.
func TestProtectedTCPSecureChannelEmitsFixedHeaderWithoutSegmentation(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	capture := &secureChannelCaptureConn{writes: make(chan []byte, 8)}
	channel := WrapSecureChannel(capture, transport, policy)

	// The measured production protected REGISTER size.
	const registerLen = 1453
	payload := bytes.Repeat([]byte{'A'}, registerLen)
	if _, err := channel.Write(payload); err != nil {
		t.Fatalf("secure channel write: %v", err)
	}

	packets := [][]byte{}
	for {
		select {
		case pkt := <-capture.writes:
			packets = append(packets, pkt)
			continue
		default:
		}
		break
	}

	if len(packets) != 1 {
		t.Fatalf("emitted %d ESP packets, want 1 (the channel does not segment)", len(packets))
	}
	inner := len(packets[0])
	t.Logf("MEASURED tcp_sip_len=%d emitted_packets=%d inner_packet_len=%d mtu=%d",
		registerLen, len(packets), inner, tcpOracleInnerMTU)

	// Cross-check the measurement against the derived model.
	if want := tcpOracleInnerLen(tcpOracleMinHeaderLen + registerLen); inner != want {
		t.Fatalf("inner packet len = %d, want %d from the ESP framing model", inner, want)
	}

	// The decisive fact: switching the ESP-protected channel to TCP as it exists
	// today does NOT avoid fragmentation, because nothing segments.
	if inner <= tcpOracleInnerMTU {
		t.Fatalf("inner packet %d unexpectedly fits %d; the no-segmentation premise changed",
			inner, tcpOracleInnerMTU)
	}
	t.Logf("MEASURED exceeds_mtu_by=%d would_fragment=true", inner-tcpOracleInnerMTU)

	// And record how much the payload would have to shrink per segment.
	t.Logf("MEASURED required_segments_at_safe_mss=%d",
		(registerLen+tcpOracleMaxPayloadForHeader(tcpOracleMinHeaderLen)-1)/
			tcpOracleMaxPayloadForHeader(tcpOracleMinHeaderLen))
}

// TestProtectedTCPSecureChannelHeaderIsSynthetic documents that the TCP header
// in the ESP path is a fixed stub, not a negotiated connection: no handshake, no
// per-segment sequence numbers, no MSS option. A real protected-TCP REGISTER
// cannot be built on it as-is.
func TestProtectedTCPSecureChannelHeaderIsSynthetic(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	capture := &secureChannelCaptureConn{writes: make(chan []byte, 8)}
	channel := WrapSecureChannel(capture, transport, policy)

	encKey, authKey := oracleExpectedKeys(policy.FlowC)
	seqNumbers := []uint32{}
	for i := 0; i < 2; i++ {
		if _, err := channel.Write([]byte("REGISTER-probe")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		esp := <-capture.writes
		parsed, err := parseIPPacket(esp)
		if err != nil {
			t.Fatalf("parseIPPacket: %v", err)
		}
		decoded := oracleDecodeESP(t, parsed.transportPayload, encKey, authKey)
		if len(decoded.plaintext) < 20 {
			t.Fatalf("TCP segment too short")
		}
		headerLen := int(decoded.plaintext[12]>>4) * 4
		if headerLen != tcpOracleMinHeaderLen {
			t.Fatalf("TCP header len = %d, want %d (no options are emitted)", headerLen, tcpOracleMinHeaderLen)
		}
		seqNumbers = append(seqNumbers, binary.BigEndian.Uint32(decoded.plaintext[4:8]))
		// Flags byte: PSH+ACK only, never SYN, so no MSS is ever advertised.
		flags := decoded.plaintext[13]
		if flags&0x02 != 0 {
			t.Fatalf("unexpected SYN flag in the ESP TCP stub")
		}
		if flags != 0x18 {
			t.Fatalf("TCP flags = %#x, want PSH+ACK 0x18", flags)
		}
	}

	// Both writes reuse the same sequence number: the stub is stateless, so a
	// peer TCP could not reassemble a multi-segment REGISTER from it.
	if seqNumbers[0] != seqNumbers[1] {
		t.Fatalf("sequence numbers %d/%d differ; the stub was expected to be stateless",
			seqNumbers[0], seqNumbers[1])
	}
	t.Logf("MEASURED tcp_header_len=%d advertises_mss=false stateless_seq=true", tcpOracleMinHeaderLen)
}

// TestProtectedTCPServerFlowIsRejected records that the TCP secure channel has
// no FlowS write path, so port-s traffic cannot use it without new code.
func TestProtectedTCPServerFlowIsRejected(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	channel := WrapSecureChannel(&secureChannelCaptureConn{writes: make(chan []byte, 4)}, transport, policy)
	if _, err := channel.WriteServerFlow([]byte("probe")); err == nil {
		t.Fatal("WriteServerFlow unexpectedly succeeded on a TCP secure channel")
	}
}
