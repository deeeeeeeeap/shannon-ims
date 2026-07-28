package voiceclient

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The protected REGISTER is fragmented by fragmentRawIPv6Packet before it enters
// the SWu tunnel, and the ePDG has to reassemble it. Nothing so far has verified
// those fragments against an independent reading of RFC 8200 - the existing
// tests only check lengths, so a wrong Fragment Offset shift, a wrong M flag bit
// or a swapped Next Header would pass unnoticed and the peer would silently drop
// the datagram.
//
// This oracle re-derives every Fragment Header field from the RFC layout by hand
// and reassembles the fragments with its own logic. It never calls
// fragmentRawIPv6Packet's inverse, because there is none in the project: that is
// exactly why an independent reassembler is required here.
//
// RFC 8200 section 4.5 Fragment Header:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Next Header  |   Reserved    |     Fragment Offset     |Res|M|
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Identification                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Fragment Offset is 13 bits in units of 8 octets, held in the TOP 13 bits of
// the 16-bit word; M is the lowest bit.
//
// No SIP text, identity, address or key material appears here: the payload is a
// deterministic byte pattern.

const (
	oracleIPv6HeaderLen  = 40
	oracleFragmentHdrLen = 8
	oracleFragmentProto  = 44
	oracleProtoESP       = 50
)

// oracleFragment is one independently parsed IPv6 fragment.
type oracleFragment struct {
	nextHeader    byte
	reserved      byte
	offsetBytes   int
	reservedBits  byte
	moreFragments bool
	identifier    uint32
	payload       []byte
}

// parseIPv6FragmentIndependently decodes a fragment straight from the RFC
// layout. It deliberately duplicates no project code.
func parseIPv6FragmentIndependently(t *testing.T, fragment []byte) oracleFragment {
	t.Helper()
	if len(fragment) < oracleIPv6HeaderLen+oracleFragmentHdrLen {
		t.Fatalf("fragment too short for IPv6 + Fragment Header: %d bytes", len(fragment))
	}
	if got := fragment[0] >> 4; got != 6 {
		t.Fatalf("fragment IP version = %d, want 6", got)
	}
	// The IPv6 Payload Length must cover the Fragment Header plus its payload.
	payloadLen := int(binary.BigEndian.Uint16(fragment[4:6]))
	if want := len(fragment) - oracleIPv6HeaderLen; payloadLen != want {
		t.Fatalf("IPv6 payload length = %d, want %d", payloadLen, want)
	}
	// The IPv6 header's Next Header must point at the Fragment Header.
	if got := fragment[6]; got != oracleFragmentProto {
		t.Fatalf("IPv6 next header = %d, want %d (Fragment)", got, oracleFragmentProto)
	}

	fh := fragment[oracleIPv6HeaderLen : oracleIPv6HeaderLen+oracleFragmentHdrLen]
	word := binary.BigEndian.Uint16(fh[2:4])
	return oracleFragment{
		nextHeader: fh[0],
		reserved:   fh[1],
		// Top 13 bits, in units of 8 octets.
		offsetBytes:   int(word>>3) * 8,
		reservedBits:  byte((word >> 1) & 0x03),
		moreFragments: word&0x01 == 1,
		identifier:    binary.BigEndian.Uint32(fh[4:8]),
		payload:       fragment[oracleIPv6HeaderLen+oracleFragmentHdrLen:],
	}
}

// reassembleIndependently rebuilds the original packet from fragments using its
// own offset bookkeeping.
func reassembleIndependently(t *testing.T, header []byte, fragments []oracleFragment) []byte {
	t.Helper()
	total := 0
	for _, f := range fragments {
		if end := f.offsetBytes + len(f.payload); end > total {
			total = end
		}
	}
	payload := make([]byte, total)
	filled := make([]bool, total)
	for _, f := range fragments {
		for i := range f.payload {
			at := f.offsetBytes + i
			if filled[at] {
				t.Fatalf("fragments overlap at payload byte %d", at)
			}
			payload[at] = f.payload[i]
			filled[at] = true
		}
	}
	for i, ok := range filled {
		if !ok {
			t.Fatalf("reassembled payload has a hole at byte %d", i)
		}
	}

	// Rebuild the unfragmented packet: original IPv6 header with the payload
	// length and Next Header restored from the fragments.
	out := make([]byte, oracleIPv6HeaderLen+len(payload))
	copy(out[:oracleIPv6HeaderLen], header)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = fragments[0].nextHeader
	copy(out[oracleIPv6HeaderLen:], payload)
	return out
}

// buildOracleIPv6ESPPacket makes an IPv6+ESP packet of a chosen total size with
// a deterministic, non-repeating payload so misplaced bytes cannot cancel out.
func buildOracleIPv6ESPPacket(totalLen int) []byte {
	packet := make([]byte, totalLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(totalLen-oracleIPv6HeaderLen))
	packet[6] = oracleProtoESP
	packet[7] = 64
	for i := 0; i < 16; i++ {
		packet[8+i] = byte(0x20 + i)  // source
		packet[24+i] = byte(0x40 + i) // destination
	}
	for i := oracleIPv6HeaderLen; i < totalLen; i++ {
		// A 2-byte stride pattern: neither constant nor 8-byte periodic, so an
		// off-by-8 offset error cannot produce an identical reassembly.
		packet[i] = byte((i*7 + (i/251)*3) & 0xff)
	}
	return packet
}

func TestIPv6ESPFragmentsMatchIndependentOracle(t *testing.T) {
	for _, tc := range []struct {
		name          string
		totalLen      int
		mtu           int
		wantFragments int
	}{
		// The size measured on device: inner packet for a 1360-byte protected
		// REGISTER. This is the case that actually goes on the wire.
		{name: "production protected register", totalLen: 1452, mtu: swuRawIPMTU, wantFragments: 2},
		// Just over the MTU: the smallest packet that fragments at all.
		{name: "one byte over mtu", totalLen: swuRawIPMTU + 1, mtu: swuRawIPMTU, wantFragments: 2},
		// Three fragments, so a middle fragment (M=1 and offset>0) is covered.
		{name: "three fragments", totalLen: 3000, mtu: swuRawIPMTU, wantFragments: 3},
		// A payload length that is not a multiple of 8, to pin the final
		// fragment's handling.
		{name: "unaligned tail", totalLen: 1285, mtu: swuRawIPMTU, wantFragments: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := buildOracleIPv6ESPPacket(tc.totalLen)

			fragments, err := fragmentRawIPPacket(original, tc.mtu)
			if err != nil {
				t.Fatalf("fragmentRawIPPacket: %v", err)
			}
			if len(fragments) != tc.wantFragments {
				t.Fatalf("fragment count = %d, want %d", len(fragments), tc.wantFragments)
			}

			parsed := make([]oracleFragment, 0, len(fragments))
			var identifier uint32
			expectedOffset := 0
			maxPayload := ((tc.mtu - oracleIPv6HeaderLen - oracleFragmentHdrLen) / 8) * 8

			for i, fragment := range fragments {
				// Every fragment must fit the MTU.
				if len(fragment) > tc.mtu {
					t.Fatalf("fragment %d is %d bytes, exceeds MTU %d", i, len(fragment), tc.mtu)
				}
				f := parseIPv6FragmentIndependently(t, fragment)

				// Next Header must carry the ORIGINAL upper-layer protocol,
				// not the Fragment protocol.
				if f.nextHeader != oracleProtoESP {
					t.Fatalf("fragment %d Fragment-Header next header = %d, want %d (ESP)",
						i, f.nextHeader, oracleProtoESP)
				}
				if f.reserved != 0 {
					t.Fatalf("fragment %d reserved octet = %d, want 0", i, f.reserved)
				}
				if f.reservedBits != 0 {
					t.Fatalf("fragment %d reserved bits = %d, want 0", i, f.reservedBits)
				}

				// Offsets must be contiguous and expressed in 8-octet units.
				if f.offsetBytes != expectedOffset {
					t.Fatalf("fragment %d offset = %d bytes, want %d", i, f.offsetBytes, expectedOffset)
				}
				if f.offsetBytes%8 != 0 {
					t.Fatalf("fragment %d offset %d is not a multiple of 8", i, f.offsetBytes)
				}

				// M must be set on every fragment but the last.
				wantMore := i < len(fragments)-1
				if f.moreFragments != wantMore {
					t.Fatalf("fragment %d M flag = %v, want %v", i, f.moreFragments, wantMore)
				}
				// Non-final fragment payloads must be a multiple of 8 octets.
				if wantMore {
					if len(f.payload)%8 != 0 {
						t.Fatalf("non-final fragment %d payload %d is not a multiple of 8", i, len(f.payload))
					}
					if len(f.payload) != maxPayload {
						t.Fatalf("non-final fragment %d payload = %d, want the full %d", i, len(f.payload), maxPayload)
					}
				}

				// Identification must be identical across the set and non-zero.
				if i == 0 {
					identifier = f.identifier
					if identifier == 0 {
						t.Fatal("fragment identification is zero")
					}
				} else if f.identifier != identifier {
					t.Fatalf("fragment %d identification = %d, want %d", i, f.identifier, identifier)
				}

				parsed = append(parsed, f)
				expectedOffset += len(f.payload)
			}

			// The independently reassembled packet must equal the original byte
			// for byte. This is the assertion that a symmetric bug cannot pass.
			rebuilt := reassembleIndependently(t, original[:oracleIPv6HeaderLen], parsed)
			if !bytes.Equal(rebuilt, original) {
				t.Fatalf("independent reassembly differs from the original: got %d bytes, want %d",
					len(rebuilt), len(original))
			}
		})
	}
}

// A packet that fits the MTU must be passed through untouched, with no Fragment
// Header inserted.
func TestIPv6PacketWithinMTUIsNotFragmented(t *testing.T) {
	original := buildOracleIPv6ESPPacket(swuRawIPMTU)
	fragments, err := fragmentRawIPPacket(original, swuRawIPMTU)
	if err != nil {
		t.Fatalf("fragmentRawIPPacket: %v", err)
	}
	if len(fragments) != 1 {
		t.Fatalf("packet count = %d, want 1", len(fragments))
	}
	if !bytes.Equal(fragments[0], original) {
		t.Fatal("an unfragmented packet was modified")
	}
	if fragments[0][6] == oracleFragmentProto {
		t.Fatal("a Fragment Header was inserted into an unfragmented packet")
	}
}

// Distinct packets must not reuse an Identification value, or a peer will merge
// unrelated fragments.
func TestIPv6FragmentIdentificationDiffersBetweenPackets(t *testing.T) {
	first, err := fragmentRawIPPacket(buildOracleIPv6ESPPacket(1452), swuRawIPMTU)
	if err != nil {
		t.Fatalf("fragmentRawIPPacket: %v", err)
	}
	second, err := fragmentRawIPPacket(buildOracleIPv6ESPPacket(1452), swuRawIPMTU)
	if err != nil {
		t.Fatalf("fragmentRawIPPacket: %v", err)
	}
	idOf := func(fragment []byte) uint32 {
		return binary.BigEndian.Uint32(fragment[oracleIPv6HeaderLen+4 : oracleIPv6HeaderLen+8])
	}
	if idOf(first[0]) == idOf(second[0]) {
		t.Fatal("two separate packets share a Fragment Identification")
	}
}
