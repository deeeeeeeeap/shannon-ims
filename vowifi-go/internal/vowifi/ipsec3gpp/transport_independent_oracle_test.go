package ipsec3gpp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"testing"
)

// Every existing transform test in this package verifies TransformOutbound by
// feeding its output back through TransformInbound. That proves the two are
// mutually consistent, not that either is correct: a symmetric mistake in the
// ESP framing (wrong ICV coverage, wrong pad bytes, wrong next-header position,
// IV placed inside the authenticated range incorrectly, ...) passes such a test
// while producing bytes no standards-compliant peer would accept.
//
// The protected REGISTER is silently dropped by the P-CSCF with no SIP or ICMP
// response and inner_esp_count stays 0 in the return direction, so "the bytes we
// emit are wrong" is still a live hypothesis that nothing has tested.
//
// This file is that test. It decodes TransformOutbound's output using ONLY the
// Go standard library (crypto/aes, crypto/cipher, crypto/hmac, crypto/sha1) and
// checks it field by field against RFC 4303 §2 and RFC 3602 §3. It must never
// call TransformInbound, decapsulateTransport, or any project decode helper.
//
// Assertions are on structure and derived lengths. No key material, address or
// payload is printed.

const (
	oracleESPHeaderLen  = 8  // SPI(4) || Sequence(4)
	oracleAESCBCIVLen   = 16 // RFC 3602 §3: IV is the AES block size
	oracleHMACSHA196Len = 12 // RFC 2404: ICV truncated to 96 bits
	oracleAESBlockLen   = 16
)

// oracleFlow returns a deterministic AES-CBC + HMAC-SHA-1-96 flow. CK/IK are
// fixed test vectors, not real key material.
func oracleFlow(spiOut, spiIn uint32, localPort, remotePort int) Flow {
	ck := make([]byte, 16)
	ik := make([]byte, 16)
	for i := range ck {
		ck[i] = byte(0x10 + i)
		ik[i] = byte(0xA0 + i)
	}
	return Flow{
		OutboundSPI: spiOut,
		InboundSPI:  spiIn,
		LocalPort:   localPort,
		RemotePort:  remotePort,
		AuthAlg:     "hmac-sha-1-96",
		EncAlg:      "aes-cbc",
		CK:          ck,
		IK:          ik,
	}
}

func oraclePolicy(t *testing.T) Policy {
	t.Helper()
	local := net.ParseIP("2607:fc20:a27c:3ab2:ac39:52db:65f0:5f80")
	remote := net.ParseIP("fd00:976a:14f7:36::5")
	if local == nil || remote == nil {
		t.Fatal("oracle test addresses failed to parse")
	}
	return Policy{
		LocalIP:     local.To16(),
		RemoteIP:    remote.To16(),
		LocalPortC:  5062,
		LocalPortS:  5063,
		RemotePortC: 6001,
		RemotePortS: 6002,
		FlowC:       oracleFlow(0x2002, 0x1001, 5062, 6002),
		FlowS:       oracleFlow(0x2001, 0x1002, 5063, 6001),
	}
}

// oracleExpectedKeys derives the ESP keys the way TS 33.203 requires, using the
// standard library only: CK_IM is the AES-CBC-128 key, IK_IM zero-extended to 20
// bytes is the HMAC-SHA-1 key.
func oracleExpectedKeys(flow Flow) (encKey, authKey []byte) {
	encKey = append([]byte(nil), flow.CK[:16]...)
	authKey = make([]byte, 20)
	copy(authKey, flow.IK[:16])
	return encKey, authKey
}

// oracleDecodedESP is what the independent decoder recovers.
type oracleDecodedESP struct {
	spi        uint32
	seq        uint32
	iv         []byte
	plaintext  []byte
	padLen     int
	padBytes   []byte
	nextHeader uint8
	icvValid   bool
}

// oracleDecodeESP parses and verifies an ESP payload per RFC 4303 using only
// the standard library. It deliberately duplicates the logic rather than
// reusing anything from this package.
func oracleDecodeESP(t *testing.T, esp []byte, encKey, authKey []byte) oracleDecodedESP {
	t.Helper()

	minLen := oracleESPHeaderLen + oracleAESCBCIVLen + oracleAESBlockLen + oracleHMACSHA196Len
	if len(esp) < minLen {
		t.Fatalf("ESP payload is %d bytes, want at least %d", len(esp), minLen)
	}

	// RFC 4303 §3.4.4.1: the ICV is computed over the ESP header, the payload
	// (IV + ciphertext) and, when present, the ESN high-order bits. It does NOT
	// cover itself.
	icvOffset := len(esp) - oracleHMACSHA196Len
	authenticated := esp[:icvOffset]
	receivedICV := esp[icvOffset:]

	mac := hmac.New(sha1.New, authKey)
	mac.Write(authenticated)
	expectedICV := mac.Sum(nil)[:oracleHMACSHA196Len]

	decoded := oracleDecodedESP{
		spi:      binary.BigEndian.Uint32(esp[0:4]),
		seq:      binary.BigEndian.Uint32(esp[4:8]),
		iv:       append([]byte(nil), esp[8:8+oracleAESCBCIVLen]...),
		icvValid: hmac.Equal(expectedICV, receivedICV),
	}

	ciphertext := esp[oracleESPHeaderLen+oracleAESCBCIVLen : icvOffset]
	if len(ciphertext) == 0 || len(ciphertext)%oracleAESBlockLen != 0 {
		t.Fatalf("ciphertext is %d bytes, want a non-zero multiple of %d", len(ciphertext), oracleAESBlockLen)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatalf("independent AES cipher: %v", err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, decoded.iv).CryptBlocks(plain, ciphertext)

	// RFC 4303 §2.4-2.6: the trailer is Padding || Pad Length || Next Header.
	decoded.padLen = int(plain[len(plain)-2])
	decoded.nextHeader = plain[len(plain)-1]
	if len(plain) < decoded.padLen+2 {
		t.Fatalf("pad length %d does not fit in %d plaintext bytes", decoded.padLen, len(plain))
	}
	payloadEnd := len(plain) - 2 - decoded.padLen
	decoded.plaintext = append([]byte(nil), plain[:payloadEnd]...)
	decoded.padBytes = append([]byte(nil), plain[payloadEnd:len(plain)-2]...)
	return decoded
}

// TestOutboundESPMatchesIndependentOracle is the core wire check: everything
// TransformOutbound emits must be recoverable and correct by an independent
// RFC 4303 decoder.
func TestOutboundESPMatchesIndependentOracle(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	// A plain inner IPv6+UDP packet on FlowC, the shape a protected REGISTER
	// takes. The SIP body is filler: this test is about framing, not content.
	sipPayload := bytes.Repeat([]byte("R"), 300)
	plainPacket, err := buildOutboundUDPPacketForFlow(policy, policy.FlowC, sipPayload)
	if err != nil {
		t.Fatalf("buildOutboundUDPPacketForFlow: %v", err)
	}

	espPacket, err := transport.TransformOutbound(plainPacket)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}

	// The result must still be an IPv6 packet whose Next Header is ESP(50) and
	// whose payload length field agrees with the actual payload.
	if espPacket[0]>>4 != 6 {
		t.Fatalf("outbound packet version = %d, want 6", espPacket[0]>>4)
	}
	if got := espPacket[6]; got != ipProtoESP {
		t.Fatalf("outbound Next Header = %d, want %d (ESP)", got, ipProtoESP)
	}
	espPayload := espPacket[40:]
	if got := int(binary.BigEndian.Uint16(espPacket[4:6])); got != len(espPayload) {
		t.Fatalf("IPv6 payload length field = %d, want %d", got, len(espPayload))
	}
	// Addresses must be preserved verbatim from the plain packet.
	if !bytes.Equal(espPacket[8:24], plainPacket[8:24]) || !bytes.Equal(espPacket[24:40], plainPacket[24:40]) {
		t.Fatal("ESP packet did not preserve the IPv6 source/destination addresses")
	}

	encKey, authKey := oracleExpectedKeys(policy.FlowC)
	decoded := oracleDecodeESP(t, espPayload, encKey, authKey)

	// 1. The ICV must verify under an independently computed HMAC-SHA-1-96.
	//    This is the single most important assertion in the file: if the
	//    project's ICV coverage is wrong, every peer drops the packet silently.
	if !decoded.icvValid {
		t.Fatal("ICV does not verify under an independent HMAC-SHA-1-96 over ESP header||IV||ciphertext")
	}

	// 2. SPI must be the outbound SPI of the matched flow.
	if decoded.spi != policy.FlowC.OutboundSPI {
		t.Fatalf("SPI = %#x, want %#x", decoded.spi, policy.FlowC.OutboundSPI)
	}

	// 3. RFC 4303 §3.3.3: the first packet on a new SA uses sequence number 1.
	if decoded.seq != 1 {
		t.Fatalf("first sequence number = %d, want 1", decoded.seq)
	}

	// 4. Transport mode: the recovered plaintext must be exactly the transport
	//    payload of the original packet, with the IPv6 header left outside.
	wantPlaintext := plainPacket[40:]
	if !bytes.Equal(decoded.plaintext, wantPlaintext) {
		t.Fatalf("recovered plaintext is %d bytes, want the original %d-byte transport payload",
			len(decoded.plaintext), len(wantPlaintext))
	}

	// 5. Next Header must name the protocol that was encapsulated (UDP), not
	//    ESP and not the IPv6 header's own value.
	if decoded.nextHeader != ipProtoUDP {
		t.Fatalf("ESP Next Header = %d, want %d (UDP)", decoded.nextHeader, ipProtoUDP)
	}

	// 6. RFC 4303 §2.4: padding bytes MUST be 1, 2, 3, ... in sequence.
	for i, b := range decoded.padBytes {
		if b != byte(i+1) {
			t.Fatalf("pad byte %d = %d, want %d per RFC 4303 2.4", i, b, i+1)
		}
	}

	// 7. The plaintext fed to AES must have been block-aligned, which is what
	//    the padding exists to guarantee.
	if total := len(decoded.plaintext) + decoded.padLen + 2; total%oracleAESBlockLen != 0 {
		t.Fatalf("payload+pad+trailer = %d, want a multiple of %d", total, oracleAESBlockLen)
	}
}

// TestOutboundESPSequenceNumbersIncrementPerSA guards RFC 4303 §3.3.3: the
// sequence number must advance monotonically, or the peer's replay window
// discards the traffic.
func TestOutboundESPSequenceNumbersIncrementPerSA(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	encKey, authKey := oracleExpectedKeys(policy.FlowC)

	for want := uint32(1); want <= 3; want++ {
		plain, err := buildOutboundUDPPacketForFlow(policy, policy.FlowC, []byte("ping"))
		if err != nil {
			t.Fatalf("buildOutboundUDPPacketForFlow: %v", err)
		}
		esp, err := transport.TransformOutbound(plain)
		if err != nil {
			t.Fatalf("TransformOutbound #%d: %v", want, err)
		}
		decoded := oracleDecodeESP(t, esp[40:], encKey, authKey)
		if !decoded.icvValid {
			t.Fatalf("packet #%d failed independent ICV verification", want)
		}
		if decoded.seq != want {
			t.Fatalf("packet #%d sequence = %d, want %d", want, decoded.seq, want)
		}
	}
}

// TestOutboundESPUsesDistinctIVsPerPacket guards RFC 3602 §3: reusing a CBC IV
// across packets under the same key leaks plaintext relationships.
func TestOutboundESPUsesDistinctIVsPerPacket(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
	encKey, authKey := oracleExpectedKeys(policy.FlowC)

	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		plain, err := buildOutboundUDPPacketForFlow(policy, policy.FlowC, []byte("same-payload"))
		if err != nil {
			t.Fatalf("buildOutboundUDPPacketForFlow: %v", err)
		}
		esp, err := transport.TransformOutbound(plain)
		if err != nil {
			t.Fatalf("TransformOutbound: %v", err)
		}
		decoded := oracleDecodeESP(t, esp[40:], encKey, authKey)
		key := string(decoded.iv)
		if seen[key] {
			t.Fatal("an AES-CBC IV was reused across ESP packets on the same SA")
		}
		seen[key] = true
	}
}

// TestOutboundESPFlowSelectionUsesCorrectSPI proves the port-to-SPI mapping is
// not swapped: a swap would encrypt under a key the P-CSCF does not expect for
// that SPI, which is exactly the kind of failure that produces silence.
func TestOutboundESPFlowSelectionUsesCorrectSPI(t *testing.T) {
	policy := oraclePolicy(t)
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	for _, tc := range []struct {
		name string
		flow Flow
	}{
		{name: "flow_c_client_to_server", flow: policy.FlowC},
		{name: "flow_s_server_to_client", flow: policy.FlowS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := buildOutboundUDPPacketForFlow(policy, tc.flow, []byte("probe"))
			if err != nil {
				t.Fatalf("buildOutboundUDPPacketForFlow: %v", err)
			}
			esp, err := transport.TransformOutbound(plain)
			if err != nil {
				t.Fatalf("TransformOutbound: %v", err)
			}
			encKey, authKey := oracleExpectedKeys(tc.flow)
			decoded := oracleDecodeESP(t, esp[40:], encKey, authKey)
			if !decoded.icvValid {
				t.Fatal("ICV failed under the key derived for this flow; the flow/SPI mapping is inconsistent")
			}
			if decoded.spi != tc.flow.OutboundSPI {
				t.Fatalf("SPI = %#x, want %#x for this flow", decoded.spi, tc.flow.OutboundSPI)
			}
		})
	}
}
