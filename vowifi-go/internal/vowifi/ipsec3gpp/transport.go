package ipsec3gpp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ipsec"
)

type transportFlow struct {
	flow Flow
	// Each direction owns a distinct SA. outboundSA is the only mutable SA:
	// NextSequenceNumber updates its atomic sequence counter. inboundSA is
	// immutable after construction; replay state is owned separately below.
	outboundSA *ipsec.SecurityAssociation
	inboundSA  *ipsec.SecurityAssociation
	replay     *ReplayWindow
}

// Transport performs userspace ESP transport-mode transforms for SIP TCP packets.
type Transport struct {
	policy             Policy
	outbound           []transportFlow
	inbound            map[uint32]*transportFlow
	outboundPackets    atomic.Uint64
	inboundPackets     atomic.Uint64
	passthroughPackets atomic.Uint64
	transformErrors    atomic.Uint64
}

// NewTransport builds a transport from an installed Policy.
func NewTransport(policy Policy) (*Transport, error) {
	if _, _, err := normalizeIPPair(policy.LocalIP, policy.RemoteIP); err != nil {
		return nil, err
	}
	t := &Transport{
		policy:  policy,
		inbound: make(map[uint32]*transportFlow),
	}
	outC, err := newTransportFlow(policy.FlowC)
	if err != nil {
		return nil, err
	}
	outS, err := newTransportFlow(policy.FlowS)
	if err != nil {
		return nil, err
	}
	t.outbound = []transportFlow{outC, outS}
	t.inbound[policy.FlowC.InboundSPI] = &t.outbound[0]
	t.inbound[policy.FlowS.InboundSPI] = &t.outbound[1]
	return t, nil
}

func newTransportFlow(flow Flow) (transportFlow, error) {
	outboundSA, err := newSAForFlow(flow, flow.OutboundSPI)
	if err != nil {
		return transportFlow{}, err
	}
	inboundSA, err := newSAForFlow(flow, flow.InboundSPI)
	if err != nil {
		return transportFlow{}, err
	}
	return transportFlow{
		flow:       flow,
		outboundSA: outboundSA,
		inboundSA:  inboundSA,
		replay:     NewReplayWindow(defaultReplayWindowSize),
	}, nil
}

func newSAForFlow(flow Flow, spi uint32) (*ipsec.SecurityAssociation, error) {
	keys, err := DeriveSecureChannelKeys(flow)
	if err != nil {
		return nil, err
	}
	enc, err := encrypterForFlow(flow.EncAlg)
	if err != nil {
		return nil, err
	}
	integ, err := integrityForFlow(flow.AuthAlg)
	if err != nil {
		return nil, err
	}
	return ipsec.NewSecurityAssociationCBC(spi, enc, keys.EncKey, integ, keys.AuthKey), nil
}

func encrypterForFlow(encAlg string) (crypto.Encrypter, error) {
	switch canonicalEncAlg(encAlg) {
	case "aes-cbc":
		return crypto.GetEncrypterWithKeyLen(12, 128)
	case "des-ede3-cbc":
		return &tripleDESCBC{}, nil
	case "null":
		return &nullEncrypter{}, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported encryption algorithm %q", encAlg)
	}
}

func integrityForFlow(authAlg string) (crypto.IntegrityAlgorithm, error) {
	switch canonicalAuthAlg(authAlg) {
	case "hmac-sha-1-96":
		alg, err := crypto.GetIntegrityAlgorithm(2)
		if err != nil {
			return nil, err
		}
		return alg, nil
	case "hmac-md5-96":
		return &hmacMD596{}, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported authentication algorithm %q", authAlg)
	}
}

// TransformOutbound ESP-encrypts a plain IPv4/IPv6+TCP packet.
func (t *Transport) TransformOutbound(packet []byte) ([]byte, error) {
	if t == nil {
		return nil, errors.New("ipsec3gpp: transport is nil")
	}
	if len(packet) == 0 {
		return nil, errors.New("ipsec3gpp: empty IP packet")
	}
	parsed, err := parseIPPacket(packet)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	flow, ok := t.matchOutbound(parsed)
	if !ok {
		t.passthroughPackets.Add(1)
		return append([]byte(nil), packet...), nil
	}
	if parsed.nextHeader != ipProtoTCP && parsed.nextHeader != ipProtoUDP {
		t.transformErrors.Add(1)
		return nil, fmt.Errorf("ipsec3gpp: unsupported outbound transport protocol %d", parsed.nextHeader)
	}
	esp, err := encapsulateTransport(parsed.transportPayload, flow.outboundSA, parsed.nextHeader)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	out, err := replaceIPPayload(parsed.header, esp, ipProtoESP)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	t.outboundPackets.Add(1)
	return out, nil
}

// TransformInbound ESP-decrypts an inbound IPv4/IPv6 packet.
func (t *Transport) TransformInbound(packet []byte) ([]byte, error) {
	if t == nil {
		return nil, errors.New("ipsec3gpp: transport is nil")
	}
	if len(packet) == 0 {
		return nil, errors.New("ipsec3gpp: empty IP packet")
	}
	parsed, err := parseIPPacket(packet)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	if parsed.nextHeader != ipProtoESP {
		t.passthroughPackets.Add(1)
		return append([]byte(nil), packet...), nil
	}
	spi, seq, err := parseESPSPISeq(parsed.transportPayload)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	flow, ok := t.inbound[spi]
	if !ok {
		t.transformErrors.Add(1)
		return nil, fmt.Errorf("ipsec3gpp: unknown inbound ESP SPI 0x%08x", spi)
	}
	if !flow.replay.Accept(seq) {
		t.transformErrors.Add(1)
		return nil, errors.New("ipsec3gpp: replay packet rejected")
	}
	plain, nextHeader, err := decapsulateTransport(parsed.transportPayload, flow.inboundSA)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	if nextHeader != ipProtoTCP && nextHeader != ipProtoUDP {
		t.transformErrors.Add(1)
		return nil, fmt.Errorf("ipsec3gpp: unsupported inbound transport protocol %d", nextHeader)
	}
	out, err := replaceIPPayload(parsed.header, plain, nextHeader)
	if err != nil {
		t.transformErrors.Add(1)
		return nil, err
	}
	t.inboundPackets.Add(1)
	return out, nil
}

// Stats returns transport counters.
func (t *Transport) Stats() TransportStats {
	if t == nil {
		return TransportStats{}
	}
	stats := TransportStats{
		OutboundPackets:    t.outboundPackets.Load(),
		InboundPackets:     t.inboundPackets.Load(),
		PassthroughPackets: t.passthroughPackets.Load(),
		TransformErrors:    t.transformErrors.Load(),
	}
	for _, flow := range t.inbound {
		if flow == nil || flow.replay == nil {
			continue
		}
		s := flow.replay.Snapshot()
		stats.Replay.Accepted += s.Accepted
		stats.Replay.Duplicate += s.Duplicate
		stats.Replay.TooOld += s.TooOld
	}
	return stats
}

func (t *Transport) matchOutbound(parsed parsedIPPacket) (*transportFlow, bool) {
	for i := range t.outbound {
		flow := &t.outbound[i]
		if !ipEqual(parsed.src, t.policy.LocalIP) || !ipEqual(parsed.dst, t.policy.RemoteIP) {
			continue
		}
		if parsed.srcPort != flow.flow.LocalPort || parsed.dstPort != flow.flow.RemotePort {
			continue
		}
		return flow, true
	}
	return nil, false
}

type parsedIPPacket struct {
	header           []byte
	transportPayload []byte
	src, dst         []byte
	srcPort, dstPort int
	nextHeader       uint8
}

const (
	ipProtoTCP = 6
	ipProtoUDP = 17
	ipProtoESP = 50
)

func parseIPPacket(packet []byte) (parsedIPPacket, error) {
	if len(packet) < 1 {
		return parsedIPPacket{}, errors.New("ipsec3gpp: IP packet too short")
	}
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4Packet(packet)
	case 6:
		return parseIPv6Packet(packet)
	default:
		return parsedIPPacket{}, fmt.Errorf("ipsec3gpp: unsupported IP version %d", packet[0]>>4)
	}
}

func parseIPv4Packet(packet []byte) (parsedIPPacket, error) {
	if len(packet) < 20 {
		return parsedIPPacket{}, errors.New("ipsec3gpp: IPv4 packet too short")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return parsedIPPacket{}, errors.New("ipsec3gpp: invalid IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl || totalLen > len(packet) {
		return parsedIPPacket{}, errors.New("ipsec3gpp: invalid IPv4 total length")
	}
	packet = packet[:totalLen]
	nextHeader := packet[9]
	header := append([]byte(nil), packet[:ihl]...)
	payload := append([]byte(nil), packet[ihl:]...)
	out := parsedIPPacket{
		header:           header,
		transportPayload: payload,
		src:              append([]byte(nil), packet[12:16]...),
		dst:              append([]byte(nil), packet[16:20]...),
		nextHeader:       nextHeader,
	}
	if (nextHeader == ipProtoTCP || nextHeader == ipProtoUDP) && len(payload) >= 4 {
		out.srcPort = int(binary.BigEndian.Uint16(payload[0:2]))
		out.dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
	}
	return out, nil
}

func parseIPv6Packet(packet []byte) (parsedIPPacket, error) {
	if len(packet) < 40 {
		return parsedIPPacket{}, errors.New("ipsec3gpp: IPv6 packet too short")
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if 40+payloadLen > len(packet) {
		return parsedIPPacket{}, errors.New("ipsec3gpp: invalid IPv6 payload length")
	}
	packet = packet[:40+payloadLen]
	nextHeader, payload, err := parseIPv6ExtensionHeaders(packet[40:], packet[6])
	if err != nil {
		return parsedIPPacket{}, err
	}
	out := parsedIPPacket{
		header:           append([]byte(nil), packet[:40]...),
		transportPayload: append([]byte(nil), payload...),
		src:              append([]byte(nil), packet[8:24]...),
		dst:              append([]byte(nil), packet[24:40]...),
		nextHeader:       nextHeader,
	}
	if (nextHeader == ipProtoTCP || nextHeader == ipProtoUDP) && len(payload) >= 4 {
		out.srcPort = int(binary.BigEndian.Uint16(payload[0:2]))
		out.dstPort = int(binary.BigEndian.Uint16(payload[2:4]))
	}
	return out, nil
}

func parseIPv6ExtensionHeaders(payload []byte, nextHeader uint8) (uint8, []byte, error) {
	for isIPv6ExtensionHeader(nextHeader) {
		if len(payload) < 2 {
			return 0, nil, errors.New("ipsec3gpp: truncated IPv6 extension header")
		}
		hdrLen := int(payload[1]+1) * 8
		if len(payload) < hdrLen {
			return 0, nil, errors.New("ipsec3gpp: truncated IPv6 extension header length")
		}
		nextHeader = payload[0]
		payload = payload[hdrLen:]
	}
	return nextHeader, payload, nil
}

func isIPv6ExtensionHeader(proto uint8) bool {
	switch proto {
	case 0, 43, 44, 51, 60, 135:
		return true
	default:
		return false
	}
}

func replaceIPPayload(header []byte, payload []byte, nextProto uint8) ([]byte, error) {
	if len(header) < 1 {
		return nil, errors.New("ipsec3gpp: missing IP header")
	}
	switch header[0] >> 4 {
	case 4:
		if len(header) < 20 {
			return nil, errors.New("ipsec3gpp: IPv4 header too short")
		}
		out := append(append([]byte(nil), header...), payload...)
		total := len(out)
		if total > 0xffff {
			return nil, errors.New("ipsec3gpp: IPv4 packet too large")
		}
		binary.BigEndian.PutUint16(out[2:4], uint16(total))
		out[9] = nextProto
		updateIPv4HeaderChecksum(out)
		return out, nil
	case 6:
		if len(header) < 40 {
			return nil, errors.New("ipsec3gpp: IPv6 header too short")
		}
		out := append(append([]byte(nil), header...), payload...)
		if len(out)-40 > 0xffff {
			return nil, errors.New("ipsec3gpp: IPv6 payload too large")
		}
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		out[6] = nextProto
		return out, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported IP version %d", header[0]>>4)
	}
}

func updateIPv4HeaderChecksum(hdr []byte) {
	if len(hdr) < 20 {
		return
	}
	hdr[10], hdr[11] = 0, 0
	sum := ipv4HeaderChecksum(hdr[:20])
	binary.BigEndian.PutUint16(hdr[10:12], sum)
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func parseESPSPISeq(esp []byte) (uint32, uint32, error) {
	if len(esp) < 8 {
		return 0, 0, errors.New("ipsec3gpp: ESP payload too short")
	}
	return binary.BigEndian.Uint32(esp[0:4]), binary.BigEndian.Uint32(esp[4:8]), nil
}

func encapsulateTransport(plaintext []byte, sa *ipsec.SecurityAssociation, nextHeader uint8) ([]byte, error) {
	if sa == nil {
		return nil, errors.New("ipsec3gpp: missing security association")
	}
	if sa.EncryptionAlg == nil {
		return nil, errors.New("ipsec3gpp: missing encryption algorithm")
	}
	seq := sa.NextSequenceNumber()
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], sa.SPI)
	binary.BigEndian.PutUint32(header[4:8], seq)

	ivSize := sa.EncryptionAlg.IVSize()
	iv, err := crypto.RandomBytes(ivSize)
	if err != nil {
		return nil, err
	}

	blockSize := sa.EncryptionAlg.BlockSize()
	neededLen := len(plaintext) + 2
	padLen := 0
	if neededLen%blockSize != 0 {
		padLen = blockSize - (neededLen % blockSize)
	}
	dataToEncrypt := make([]byte, len(plaintext)+padLen+2)
	copy(dataToEncrypt, plaintext)
	for i := 0; i < padLen; i++ {
		dataToEncrypt[len(plaintext)+i] = byte(i + 1)
	}
	dataToEncrypt[len(plaintext)+padLen] = byte(padLen)
	dataToEncrypt[len(plaintext)+padLen+1] = nextHeader

	ciphertext, err := sa.EncryptionAlg.Encrypt(dataToEncrypt, sa.EncryptionKey, iv, header)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(header)+len(iv)+len(ciphertext))
	out = append(out, header...)
	out = append(out, iv...)
	out = append(out, ciphertext...)

	if !sa.IsAEAD && sa.IntegrityAlg2 != nil {
		icv := sa.IntegrityAlg2.Compute(sa.IntegrityKey, out)
		out = append(out, icv...)
	}
	return out, nil
}

func decapsulateTransport(packet []byte, sa *ipsec.SecurityAssociation) ([]byte, uint8, error) {
	if sa == nil {
		return nil, 0, errors.New("ipsec3gpp: missing security association")
	}
	if len(packet) < 8 {
		return nil, 0, errors.New("ipsec3gpp: ESP packet too short")
	}
	ivSize := sa.EncryptionAlg.IVSize()
	if len(packet) < 8+ivSize {
		return nil, 0, errors.New("ipsec3gpp: ESP packet too short for IV")
	}

	var ciphertext []byte
	if !sa.IsAEAD && sa.IntegrityAlg2 != nil {
		icvSize := sa.IntegrityAlg2.OutputSize()
		if len(packet) < 8+ivSize+icvSize {
			return nil, 0, errors.New("ipsec3gpp: ESP packet too short for ICV")
		}
		receivedICV := packet[len(packet)-icvSize:]
		dataToVerify := packet[:len(packet)-icvSize]
		if !sa.IntegrityAlg2.Verify(sa.IntegrityKey, dataToVerify, receivedICV) {
			return nil, 0, errors.New("ipsec3gpp: ESP integrity check failed")
		}
		ciphertext = packet[8+ivSize : len(packet)-icvSize]
	} else {
		ciphertext = packet[8+ivSize:]
	}

	iv := packet[8 : 8+ivSize]
	plaintext, err := sa.EncryptionAlg.Decrypt(ciphertext, sa.EncryptionKey, iv, packet[0:8])
	if err != nil {
		return nil, 0, err
	}
	if len(plaintext) < 2 {
		return nil, 0, errors.New("ipsec3gpp: decrypted payload too short")
	}
	padLen := int(plaintext[len(plaintext)-2])
	if len(plaintext) < 2+padLen {
		return nil, 0, errors.New("ipsec3gpp: invalid padding length")
	}
	nextHeader := plaintext[len(plaintext)-1]
	return plaintext[:len(plaintext)-2-padLen], nextHeader, nil
}
