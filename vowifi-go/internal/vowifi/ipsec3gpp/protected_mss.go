package ipsec3gpp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This file owns the one number that decides whether a protected SIP-over-TCP
// request crosses the SWu tunnel intact: the largest TCP segment whose ESP
// packet still fits the tunnel's raw IP MTU.
//
// It is derived from the negotiated transform, never hardcoded. An earlier
// attempt to reach the same goal by shrinking the gVisor link MTU failed,
// because ipv6.calculateNetworkMTU rejects any link MTU below the RFC 8200
// minimum of 1280 and a local ICMPv6 Packet Too Big below that minimum is
// folded to zero, collapsing the send budget to one byte per segment. The
// remaining lever is the MSS: what we advertise bounds the peer, and what the
// peer advertised - clamped locally, after ESP verification, on the decrypted
// copy only - bounds us, because gVisor feeds the SYN/SYN-ACK MSS straight into
// its sender.
//
// Everything here is arithmetic over lengths. No key material, address, SPI or
// payload is stored, logged or returned.

const (
	// ProtectedTunnelMTU is the raw IP MTU of the SWu tunnel, matching
	// voiceclient's swuRawIPMTU. A protected packet larger than this is
	// fragmented by the tunnel writer, which is what this whole path exists to
	// avoid.
	ProtectedTunnelMTU = 1280

	// protectedIPv6HeaderLen is the fixed IPv6 header. ipsec-3gpp transport mode
	// keeps the original header, so no extension headers are added.
	protectedIPv6HeaderLen = 40

	// protectedESPHeaderLen is SPI(4) || Sequence Number(4) per RFC 4303 §2.
	protectedESPHeaderLen = 8

	// protectedESPTrailerLen is Pad Length(1) || Next Header(1) per RFC 4303 §2.
	protectedESPTrailerLen = 2

	// protectedMinTCPHeaderLen is a TCP header with no options.
	protectedMinTCPHeaderLen = 20
)

// espTransformBudget is the per-packet framing overhead of one flow's ESP
// transform: the IV that precedes the ciphertext, the ICV that follows it, the
// cipher block the plaintext is padded up to, and the fixed trailer.
type espTransformBudget struct {
	ivLen      int
	icvLen     int
	blockLen   int
	trailerLen int
}

// espBudgetForFlow derives the framing overhead from the flow's negotiated
// algorithms.
//
// Unknown algorithms fail closed. Guessing here would mean advertising an MSS
// that is too large for the real transform, and the symptom would be a silently
// fragmented protected REGISTER - exactly the failure this path removes.
func espBudgetForFlow(flow Flow) (espTransformBudget, error) {
	budget := espTransformBudget{trailerLen: protectedESPTrailerLen}
	switch canonicalEncAlg(flow.EncAlg) {
	case "aes-cbc":
		// RFC 3602: the IV is one AES block.
		budget.ivLen, budget.blockLen = 16, 16
	case "des-ede3-cbc":
		budget.ivLen, budget.blockLen = 8, 8
	case "null":
		// RFC 2410 has no IV; RFC 4303 §2.4 still requires 4-byte alignment.
		budget.ivLen, budget.blockLen = 0, 4
	default:
		return espTransformBudget{}, errors.New("ipsec3gpp: unsupported encryption algorithm for MSS derivation")
	}
	switch canonicalAuthAlg(flow.AuthAlg) {
	case "hmac-sha-1-96", "hmac-md5-96":
		// RFC 2404 / RFC 2403: ICV truncated to 96 bits.
		budget.icvLen = 12
	default:
		return espTransformBudget{}, errors.New("ipsec3gpp: unsupported authentication algorithm for MSS derivation")
	}
	return budget, nil
}

// DeriveMaxTCPSegmentLen returns the largest TCP header+payload whose ESP packet
// still fits innerMTU:
//
//	inner = IPv6 + ESPHeader + IV + roundUp(block, segment+trailer) + ICV
//
// The padding step is why a plain subtraction is wrong: the ciphertext is
// block-aligned before framing, so the usable space must be rounded DOWN to a
// block boundary before the trailer is removed.
func DeriveMaxTCPSegmentLen(flow Flow, innerMTU int) (int, error) {
	budget, err := espBudgetForFlow(flow)
	if err != nil {
		return 0, err
	}
	usable := innerMTU - protectedIPv6HeaderLen - protectedESPHeaderLen - budget.ivLen - budget.icvLen
	if usable <= 0 {
		return 0, errors.New("ipsec3gpp: ESP overhead leaves no room for a TCP segment")
	}
	usable -= usable % budget.blockLen
	segLen := usable - budget.trailerLen
	if segLen <= protectedMinTCPHeaderLen {
		return 0, errors.New("ipsec3gpp: derived TCP segment budget is degenerate")
	}
	return segLen, nil
}

// DeriveSafeMSS is the MSS to advertise, and the ceiling to clamp a peer's
// advertisement to: the maximum segment minus a minimum TCP header.
//
// gVisor subtracts its own maxOptionSize() from the payload when it segments, so
// TCP options shrink the payload rather than growing the segment. The total
// segment therefore stays within DeriveMaxTCPSegmentLen even when timestamps or
// SACK blocks are present, which is precisely the property a hardcoded MSS would
// lose.
func DeriveSafeMSS(flow Flow, innerMTU int) (int, error) {
	segLen, err := DeriveMaxTCPSegmentLen(flow, innerMTU)
	if err != nil {
		return 0, err
	}
	return segLen - protectedMinTCPHeaderLen, nil
}

// PredictProtectedESPLen reports the ESP packet length a cleartext IP packet of
// cleartextLen bytes will become under this flow's transform. The link endpoint
// uses it to hold back an over-budget packet BEFORE protecting it.
func PredictProtectedESPLen(flow Flow, cleartextLen int) (int, error) {
	if cleartextLen < protectedIPv6HeaderLen {
		return 0, errors.New("ipsec3gpp: cleartext packet is shorter than an IPv6 header")
	}
	budget, err := espBudgetForFlow(flow)
	if err != nil {
		return 0, err
	}
	plain := cleartextLen - protectedIPv6HeaderLen + budget.trailerLen
	blocks := (plain + budget.blockLen - 1) / budget.blockLen
	return protectedIPv6HeaderLen + protectedESPHeaderLen + budget.ivLen +
		blocks*budget.blockLen + budget.icvLen, nil
}

// MSSClampResult classifies what a clamp attempt found, for logging. It carries
// no address, port, SPI or payload - only a bucket name and the resulting value.
type MSSClampResult struct {
	// Bucket is one of: below_safe, equal_safe, above_safe, missing, malformed,
	// not_applicable.
	Bucket string
	// EffectiveMSS is the value the local stack will use. Zero when the clamp
	// failed closed.
	EffectiveMSS int
	// Applied reports whether the local copy was rewritten.
	Applied bool
}

const (
	mssBucketBelowSafe     = "below_safe"
	mssBucketEqualSafe     = "equal_safe"
	mssBucketAboveSafe     = "above_safe"
	mssBucketMissing       = "missing"
	mssBucketMalformed     = "malformed"
	mssBucketNotApplicable = "not_applicable"
)

// tcpFlagSYN and tcpFlagACK are the two flags that identify the handshake
// segments whose MSS option matters.
const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

// ClampHandshakeMSS rewrites the MSS option of a SYN or SYN-ACK down to
// safeMSS, returning a modified COPY.
//
// Contract, and the reason each part exists:
//
//   - The caller must have already verified the packet's ESP integrity and
//     replay state. Rewriting an unauthenticated segment would let an off-path
//     packet steer our send budget.
//   - Only the returned copy is modified. The verified wire packet is never
//     touched, never re-encrypted and never sent back.
//   - A missing, duplicated, zero or wrong-length MSS option is an error, not a
//     default. Inventing an option here would mean guessing what the peer can
//     receive.
//
// A non-TCP packet, or a TCP segment that is not a SYN, returns
// (packet, not_applicable) without error: the ingress path hands every packet
// through, and only handshake segments carry an MSS.
func ClampHandshakeMSS(packet []byte, safeMSS int) ([]byte, MSSClampResult, error) {
	if safeMSS <= 0 {
		return nil, MSSClampResult{}, errors.New("ipsec3gpp: safe MSS must be positive")
	}
	if len(packet) < protectedIPv6HeaderLen {
		return nil, MSSClampResult{}, errors.New("ipsec3gpp: short IPv6 packet")
	}
	if packet[0]>>4 != 6 || packet[6] != ipProtoTCP {
		return packet, MSSClampResult{Bucket: mssBucketNotApplicable}, nil
	}
	seg := packet[protectedIPv6HeaderLen:]
	if len(seg) < protectedMinTCPHeaderLen {
		return nil, MSSClampResult{Bucket: mssBucketMalformed}, errors.New("ipsec3gpp: short TCP segment")
	}
	if seg[13]&tcpFlagSYN == 0 {
		// Not a handshake segment: no MSS option is expected or allowed.
		return packet, MSSClampResult{Bucket: mssBucketNotApplicable}, nil
	}
	headerLen := int(seg[12]>>4) * 4
	if headerLen < protectedMinTCPHeaderLen || headerLen > len(seg) {
		return nil, MSSClampResult{Bucket: mssBucketMalformed}, errors.New("ipsec3gpp: invalid TCP data offset")
	}

	options := seg[protectedMinTCPHeaderLen:headerLen]
	mssOffset, seen := -1, 0
	for i := 0; i < len(options); {
		switch options[i] {
		case 0: // End of option list.
			i = len(options)
		case 1: // No-Operation.
			i++
		default:
			if i+1 >= len(options) {
				return nil, MSSClampResult{Bucket: mssBucketMalformed},
					errors.New("ipsec3gpp: truncated TCP option")
			}
			optLen := int(options[i+1])
			if optLen < 2 || i+optLen > len(options) {
				return nil, MSSClampResult{Bucket: mssBucketMalformed},
					errors.New("ipsec3gpp: invalid TCP option length")
			}
			if options[i] == 2 {
				if optLen != 4 {
					return nil, MSSClampResult{Bucket: mssBucketMalformed},
						errors.New("ipsec3gpp: invalid MSS option length")
				}
				seen++
				mssOffset = protectedMinTCPHeaderLen + i
			}
			i += optLen
		}
	}
	if seen == 0 || mssOffset < 0 {
		return nil, MSSClampResult{Bucket: mssBucketMissing},
			errors.New("ipsec3gpp: handshake segment carries no MSS option")
	}
	if seen > 1 {
		return nil, MSSClampResult{Bucket: mssBucketMalformed},
			errors.New("ipsec3gpp: handshake segment carries multiple MSS options")
	}

	peerMSS := int(binary.BigEndian.Uint16(seg[mssOffset+2 : mssOffset+4]))
	if peerMSS == 0 {
		return nil, MSSClampResult{Bucket: mssBucketMalformed},
			errors.New("ipsec3gpp: MSS option is zero")
	}
	if peerMSS < safeMSS {
		return packet, MSSClampResult{Bucket: mssBucketBelowSafe, EffectiveMSS: peerMSS}, nil
	}
	if peerMSS == safeMSS {
		return packet, MSSClampResult{Bucket: mssBucketEqualSafe, EffectiveMSS: peerMSS}, nil
	}

	// Rewrite the copy only.
	out := append([]byte(nil), packet...)
	outSeg := out[protectedIPv6HeaderLen:]
	binary.BigEndian.PutUint16(outSeg[mssOffset+2:mssOffset+4], uint16(safeMSS))
	if err := rewriteTCPChecksum(out); err != nil {
		return nil, MSSClampResult{Bucket: mssBucketMalformed}, err
	}
	return out, MSSClampResult{Bucket: mssBucketAboveSafe, EffectiveMSS: safeMSS, Applied: true}, nil
}

// rewriteTCPChecksum recomputes the TCP checksum of an IPv6+TCP packet in place.
func rewriteTCPChecksum(packet []byte) error {
	if len(packet) < protectedIPv6HeaderLen+protectedMinTCPHeaderLen {
		return errors.New("ipsec3gpp: packet too short for a TCP checksum")
	}
	seg := packet[protectedIPv6HeaderLen:]
	seg[16], seg[17] = 0, 0
	sum := tcpPseudoHeaderChecksum(packet[8:24], packet[24:40], seg)
	binary.BigEndian.PutUint16(seg[16:18], sum)
	return nil
}

// tcpPseudoHeaderChecksum is the RFC 8200 §8.1 upper-layer checksum over the
// IPv6 pseudo-header and the TCP segment.
func tcpPseudoHeaderChecksum(src, dst, segment []byte) uint16 {
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
	add([]byte{0, 0, 0, ipProtoTCP})
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if out := ^uint16(sum); out != 0 {
		return out
	}
	// RFC 768 zero-is-0xffff convention; TCP has no such exemption, but a zero
	// checksum would read as "not computed" to some stacks.
	return 0xffff
}

// ProtectedMSSPlan is the pair of MSS values a protected TCP flow needs.
type ProtectedMSSPlan struct {
	// SafeMSS is advertised in our SYN/SYN-ACK and is the clamp ceiling for the
	// peer's advertisement.
	SafeMSS int
	// MaxSegmentLen is the derived TCP header+payload ceiling.
	MaxSegmentLen int
}

// PlanProtectedMSS derives both flows' budgets and requires them to agree.
//
// FlowC and FlowS are negotiated together and always share algorithms, so a
// disagreement means the policy was built inconsistently; failing here is
// cheaper than discovering it as a fragmented packet on one direction only.
func PlanProtectedMSS(policy Policy, innerMTU int) (ProtectedMSSPlan, error) {
	segC, err := DeriveMaxTCPSegmentLen(policy.FlowC, innerMTU)
	if err != nil {
		return ProtectedMSSPlan{}, fmt.Errorf("ipsec3gpp: client flow MSS: %w", err)
	}
	segS, err := DeriveMaxTCPSegmentLen(policy.FlowS, innerMTU)
	if err != nil {
		return ProtectedMSSPlan{}, fmt.Errorf("ipsec3gpp: server flow MSS: %w", err)
	}
	if segC != segS {
		return ProtectedMSSPlan{}, errors.New("ipsec3gpp: client and server flows derive different TCP budgets")
	}
	return ProtectedMSSPlan{SafeMSS: segC - protectedMinTCPHeaderLen, MaxSegmentLen: segC}, nil
}
