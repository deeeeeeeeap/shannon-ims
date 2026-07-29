package voiceclient

import "encoding/binary"

// swuTCPConservativeMSSCap keeps ordinary TCP below the observed SWu path's
// near-MTU black-hole boundary. SIP bytes, UDP, raw ESP and protected TCP are
// unchanged.
const swuTCPConservativeMSSCap = 1024

// clampSWUTCPHandshakeMSS rewrites an oversized peer MSS on a local copy of a
// SYN/SYN-ACK. The packet has already crossed the authenticated SWu dataplane;
// the rewritten copy is injected only into gVisor and is never sent on wire.
// Malformed, missing and non-handshake options are left to the TCP stack.
func clampSWUTCPHandshakeMSS(packet []byte, safeMSS int) []byte {
	segmentOffset, segmentEnd, ok := swuTCPSegmentBounds(packet)
	if !ok || safeMSS <= 0 || safeMSS > 0xffff {
		return packet
	}
	segment := packet[segmentOffset:segmentEnd]
	if len(segment) < 20 || segment[13]&0x02 == 0 {
		return packet
	}
	headerLen := int(segment[12]>>4) * 4
	if headerLen < 20 || headerLen > len(segment) {
		return packet
	}

	options := segment[20:headerLen]
	mssOffset := -1
	seen := 0
	for i := 0; i < len(options); {
		switch options[i] {
		case 0:
			i = len(options)
		case 1:
			i++
		default:
			if i+1 >= len(options) {
				return packet
			}
			optionLen := int(options[i+1])
			if optionLen < 2 || i+optionLen > len(options) {
				return packet
			}
			if options[i] == 2 {
				if optionLen != 4 {
					return packet
				}
				seen++
				mssOffset = segmentOffset + 20 + i
			}
			i += optionLen
		}
	}
	if seen != 1 || mssOffset < 0 {
		return packet
	}
	peerMSS := int(binary.BigEndian.Uint16(packet[mssOffset+2 : mssOffset+4]))
	if peerMSS == 0 || peerMSS <= safeMSS {
		return packet
	}

	out := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(out[mssOffset+2:mssOffset+4], uint16(safeMSS))
	rewriteSWUTCPChecksum(out, segmentOffset, segmentEnd)
	return out
}

func swuTCPSegmentBounds(packet []byte) (int, int, bool) {
	if len(packet) == 0 {
		return 0, 0, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || packet[9] != 6 {
			return 0, 0, false
		}
		headerLen := int(packet[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLen < 20 || totalLen < headerLen+20 || totalLen > len(packet) {
			return 0, 0, false
		}
		return headerLen, totalLen, true
	case 6:
		if len(packet) < 40 || packet[6] != 6 {
			return 0, 0, false
		}
		totalLen := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalLen < 60 || totalLen > len(packet) {
			return 0, 0, false
		}
		return 40, totalLen, true
	default:
		return 0, 0, false
	}
}

func rewriteSWUTCPChecksum(packet []byte, segmentOffset, segmentEnd int) {
	segment := packet[segmentOffset:segmentEnd]
	segment[16], segment[17] = 0, 0
	var sum uint32
	add := func(data []byte) {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data[:2]))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}

	switch packet[0] >> 4 {
	case 4:
		add(packet[12:16])
		add(packet[16:20])
		add([]byte{0, 6})
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(segment)))
		add(length[:])
	case 6:
		add(packet[8:24])
		add(packet[24:40])
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(segment)))
		add(length[:])
		add([]byte{0, 0, 0, 6})
	}
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[16:18], checksum)
}
