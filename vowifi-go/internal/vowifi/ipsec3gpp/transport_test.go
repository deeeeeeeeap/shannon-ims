package ipsec3gpp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestNewPolicyAndTransport(t *testing.T) {
	ck := bytes.Repeat([]byte{0x01}, 16)
	ik := bytes.Repeat([]byte{0x02}, 16)
	policy, err := NewPolicy(PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.1"),
		CK:       ck,
		IK:       ik,
		AuthAlg:  "hmac-sha-1-96",
		EncAlg:   "aes-cbc",
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x11111111,
			SPIs:  0x22222222,
			PortC: 6054,
			PortS: 6060,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	if policy.FlowC.OutboundSPI != 0x22222222 || policy.FlowS.OutboundSPI != 0x11111111 {
		t.Fatalf("unexpected flow SPIs: %+v %+v", policy.FlowC, policy.FlowS)
	}
	if _, err := NewTransport(policy); err != nil {
		t.Fatalf("NewTransport: %v", err)
	}
}

func TestTransportOutboundInboundIPv4(t *testing.T) {
	ck := bytes.Repeat([]byte{0x01}, 16)
	ik := bytes.Repeat([]byte{0x02}, 16)
	policy, err := NewPolicy(PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.1"),
		CK:       ck,
		IK:       ik,
		AuthAlg:  "hmac-sha-1-96",
		EncAlg:   "aes-cbc",
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x11111111,
			SPIs:  0x22222222,
			PortC: 6054,
			PortS: 6060,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	sip := []byte("REGISTER sip:ims.example.org SIP/2.0\r\n\r\n")
	plainPacket, err := buildOutboundTCPPacket(policy, sip)
	if err != nil {
		t.Fatalf("buildOutboundTCPPacket: %v", err)
	}
	encrypted, err := transport.TransformOutbound(plainPacket)
	if err != nil {
		t.Fatalf("TransformOutbound: %v", err)
	}
	parsed, err := parseIPPacket(encrypted)
	if err != nil {
		t.Fatalf("parseIPPacket encrypted: %v", err)
	}
	if parsed.nextHeader != ipProtoESP {
		t.Fatalf("expected ESP protocol, got %d", parsed.nextHeader)
	}

	// Simulate a server-originated ESP packet (SPIs) back to the UE.
	serverFlow := transport.outbound[1]
	tcpPayload := buildMinimalTCPSegment(policy.FlowS.RemotePort, policy.FlowS.LocalPort, sip)
	esp, err := encapsulateTransport(tcpPayload, serverFlow.outboundSA, ipProtoTCP)
	if err != nil {
		t.Fatalf("encapsulateTransport: %v", err)
	}
	inboundIP := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, esp)
	decrypted, err := transport.TransformInbound(inboundIP)
	if err != nil {
		t.Fatalf("TransformInbound: %v", err)
	}
	gotParsed, err := parseIPPacket(decrypted)
	if err != nil {
		t.Fatalf("parseIPPacket decrypted: %v", err)
	}
	if !bytes.Contains(gotParsed.transportPayload, sip) {
		t.Fatalf("missing SIP payload in %x", gotParsed.transportPayload)
	}
}

func TestReplaceIPv4PayloadChecksumCoversOptions(t *testing.T) {
	header := make([]byte, 24)
	header[0] = 0x46
	header[8] = 64
	header[9] = ipProtoUDP
	copy(header[12:16], net.ParseIP("10.0.0.2").To4())
	copy(header[16:20], net.ParseIP("10.0.0.1").To4())
	copy(header[20:24], []byte{0x01, 0x02, 0x03, 0x04})

	out, err := replaceIPPayload(header, []byte{0x00, 0x01, 0x00, 0x02}, ipProtoTCP)
	if err != nil {
		t.Fatalf("replaceIPPayload() error=%v", err)
	}
	if !bytes.Equal(out[20:24], header[20:24]) {
		t.Fatalf("IPv4 options changed: got=%x want=%x", out[20:24], header[20:24])
	}
	if got := ipv4HeaderChecksum(out[:24]); got != 0 {
		t.Fatalf("IPv4 checksum over IHL=6 header = 0x%04x, want 0", got)
	}
}

func TestReplaceIPv6PayloadPreservesHopByHopHeaderChain(t *testing.T) {
	src := net.ParseIP("2001:db8::2").To16()
	dst := net.ParseIP("2001:db8::1").To16()
	hopByHop := []byte{ipProtoUDP, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	udp := []byte{0x13, 0xc4, 0x13, 0xc5, 0x00, 0x08, 0x00, 0x00}
	packet := buildIPv6Packet(src, dst, 0, append(append([]byte(nil), hopByHop...), udp...))

	parsed, err := parseIPPacket(packet)
	if err != nil {
		t.Fatalf("parseIPPacket() error=%v", err)
	}
	if parsed.nextHeader != ipProtoUDP || len(parsed.header) != 48 {
		t.Fatalf("parsed IPv6 chain = next:%d header_len:%d, want UDP/48", parsed.nextHeader, len(parsed.header))
	}

	espPayload := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	out, err := replaceIPPayload(parsed.header, espPayload, ipProtoESP)
	if err != nil {
		t.Fatalf("replaceIPPayload() error=%v", err)
	}
	if out[6] != 0 {
		t.Fatalf("IPv6 base Next Header=%d, want Hop-by-Hop (0)", out[6])
	}
	if out[40] != ipProtoESP {
		t.Fatalf("Hop-by-Hop Next Header=%d, want ESP", out[40])
	}
	if !bytes.Equal(out[41:48], hopByHop[1:]) {
		t.Fatalf("Hop-by-Hop header changed: got=%x want=%x", out[40:48], append([]byte{ipProtoESP}, hopByHop[1:]...))
	}
	if !bytes.Equal(out[48:], espPayload) {
		t.Fatalf("ESP payload changed: got=%x want=%x", out[48:], espPayload)
	}
}

func TestReplaceIPv6PayloadPreservesDestinationRoutingAndAHHeaders(t *testing.T) {
	src := net.ParseIP("2001:db8::2").To16()
	dst := net.ParseIP("2001:db8::1").To16()
	udp := []byte{0x13, 0xc4, 0x13, 0xc5, 0x00, 0x08, 0x00, 0x00}
	tests := []struct {
		name       string
		firstProto uint8
		extensions []byte
		lastOffset int
	}{
		{
			name:       "destination",
			firstProto: 60,
			extensions: []byte{ipProtoUDP, 0, 1, 2, 3, 4, 5, 6},
			lastOffset: 40,
		},
		{
			name:       "routing",
			firstProto: 43,
			extensions: []byte{ipProtoUDP, 0, 1, 2, 3, 4, 5, 6},
			lastOffset: 40,
		},
		{
			name:       "ah-12-bytes",
			firstProto: 51,
			extensions: []byte{ipProtoUDP, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2},
			lastOffset: 40,
		},
		{
			name:       "destination-routing-ah-chain",
			firstProto: 60,
			extensions: append(append(
				[]byte{43, 0, 1, 2, 3, 4, 5, 6},
				[]byte{51, 0, 7, 8, 9, 10, 11, 12}...,
			), []byte{ipProtoUDP, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2}...),
			lastOffset: 56,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := buildIPv6Packet(src, dst, tt.firstProto, append(append([]byte(nil), tt.extensions...), udp...))
			parsed, err := parseIPPacket(packet)
			if err != nil {
				t.Fatalf("parseIPPacket() error=%v", err)
			}
			if parsed.nextHeader != ipProtoUDP {
				t.Fatalf("parsed Next Header=%d, want UDP", parsed.nextHeader)
			}
			if len(parsed.header) != 40+len(tt.extensions) {
				t.Fatalf("parsed header length=%d, want %d", len(parsed.header), 40+len(tt.extensions))
			}
			out, err := replaceIPPayload(parsed.header, []byte{0xaa}, ipProtoESP)
			if err != nil {
				t.Fatalf("replaceIPPayload() error=%v", err)
			}
			if out[6] != tt.firstProto || out[tt.lastOffset] != ipProtoESP {
				t.Fatalf("Next Header chain changed incorrectly: base=%d final=%d", out[6], out[tt.lastOffset])
			}
			if !bytes.Equal(out[40:tt.lastOffset], tt.extensions[:tt.lastOffset-40]) || !bytes.Equal(out[tt.lastOffset+1:40+len(tt.extensions)], tt.extensions[tt.lastOffset-39:]) {
				t.Fatalf("extension chain bytes changed: got=%x want=%x", out[40:40+len(tt.extensions)], tt.extensions)
			}
		})
	}
}

func TestTransportRejectsTargetIPv4NonInitialFragment(t *testing.T) {
	policy := secureChannelUDPTestPolicy(t, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3"))
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport() error=%v", err)
	}
	packet := buildIPv4Packet(policy.LocalIP, policy.RemoteIP, ipProtoUDP, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11})
	binary.BigEndian.PutUint16(packet[6:8], 1)
	updateIPv4HeaderChecksum(packet)

	if out, err := transport.TransformOutbound(packet); err == nil {
		t.Fatalf("TransformOutbound() accepted non-initial target fragment; passthrough=%v", bytes.Equal(out, packet))
	}
}

func TestTransportRejectsInboundTargetIPv4FragmentBeforePassthrough(t *testing.T) {
	policy := secureChannelUDPTestPolicy(t, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3"))
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport() error=%v", err)
	}
	packet := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoUDP, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11})
	binary.BigEndian.PutUint16(packet[6:8], 1)
	updateIPv4HeaderChecksum(packet)

	if out, err := transport.TransformInbound(packet); err == nil {
		t.Fatalf("TransformInbound() accepted fragmented inbound policy packet; passthrough=%v", bytes.Equal(out, packet))
	}
}

func TestTransportRejectsTargetIPv6FragmentHeader(t *testing.T) {
	policy := secureChannelUDPTestPolicy(t, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::3"))
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport() error=%v", err)
	}
	fragmentHeader := make([]byte, 8)
	fragmentHeader[0] = ipProtoUDP
	binary.BigEndian.PutUint16(fragmentHeader[2:4], 1<<3)
	binary.BigEndian.PutUint32(fragmentHeader[4:8], 0x01020304)
	fragmentPayload := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	packet := buildIPv6Packet(policy.LocalIP, policy.RemoteIP, 44, append(fragmentHeader, fragmentPayload...))

	if out, err := transport.TransformOutbound(packet); err == nil {
		t.Fatalf("TransformOutbound() accepted IPv6 Fragment Header; passthrough=%v", bytes.Equal(out, packet))
	}
}

func TestTransportRejectsTargetIPv4InitialFragmentWithMoreFlag(t *testing.T) {
	policy := secureChannelUDPTestPolicy(t, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3"))
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport() error=%v", err)
	}
	packet, err := buildOutboundUDPPacket(policy, []byte("synthetic"))
	if err != nil {
		t.Fatalf("buildOutboundUDPPacket() error=%v", err)
	}
	binary.BigEndian.PutUint16(packet[6:8], 0x2000)
	updateIPv4HeaderChecksum(packet)
	if _, err := transport.TransformOutbound(packet); err == nil {
		t.Fatal("TransformOutbound() accepted IPv4 first fragment with MF=1")
	}
}

func TestTransportRejectsInboundTargetIPv6FragmentHeader(t *testing.T) {
	policy := secureChannelUDPTestPolicy(t, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::3"))
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport() error=%v", err)
	}
	fragmentHeader := make([]byte, 8)
	fragmentHeader[0] = ipProtoUDP
	binary.BigEndian.PutUint16(fragmentHeader[2:4], 1)
	binary.BigEndian.PutUint32(fragmentHeader[4:8], 0x01020304)
	packet := buildIPv6Packet(policy.RemoteIP, policy.LocalIP, 44, append(fragmentHeader, []byte{1, 2, 3, 4}...))
	if out, err := transport.TransformInbound(packet); err == nil {
		t.Fatalf("TransformInbound() accepted IPv6 Fragment Header; passthrough=%v", bytes.Equal(out, packet))
	}
}

func TestTransportInvalidHighSequenceDoesNotAdvanceReplayWindow(t *testing.T) {
	policy, err := NewPolicy(PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.1"),
		CK:       bytes.Repeat([]byte{0x01}, 16),
		IK:       bytes.Repeat([]byte{0x02}, 16),
		AuthAlg:  "hmac-sha-1-96",
		EncAlg:   "aes-cbc",
		Mech: SecurityMechanism{
			Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Prot: "esp", Mode: "trans",
			SPIc: 0x11111111, SPIs: 0x22222222, PortC: 6054, PortS: 6060,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	serverFlow := transport.outbound[1]
	tcpPayload := buildMinimalTCPSegment(
		policy.FlowS.RemotePort,
		policy.FlowS.LocalPort,
		[]byte("REGISTER sip:ims.example.org SIP/2.0\r\n\r\n"),
	)
	badESP, err := encapsulateTransport(tcpPayload, serverFlow.outboundSA, ipProtoTCP)
	if err != nil {
		t.Fatalf("encapsulateTransport(bad): %v", err)
	}
	badESP = append([]byte(nil), badESP...)
	binary.BigEndian.PutUint32(badESP[4:8], 1000) // invalidate the existing ICV
	badPacket := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, badESP)
	if _, err := transport.TransformInbound(badPacket); err == nil {
		t.Fatal("TransformInbound(bad ICV) error = nil, want integrity rejection")
	}
	if got := transport.Stats().Replay.Accepted; got != 0 {
		t.Fatalf("replay accepted after bad ICV = %d, want 0", got)
	}

	validESP, err := encapsulateTransport(tcpPayload, serverFlow.outboundSA, ipProtoTCP)
	if err != nil {
		t.Fatalf("encapsulateTransport(valid): %v", err)
	}
	validPacket := buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, validESP)
	if _, err := transport.TransformInbound(validPacket); err != nil {
		t.Fatalf("TransformInbound(valid after bad high sequence): %v", err)
	}
	if _, err := transport.TransformInbound(validPacket); err == nil {
		t.Fatal("TransformInbound(authenticated duplicate) error = nil, want replay rejection")
	}
	stats := transport.Stats().Replay
	if stats.Accepted != 1 || stats.Duplicate != 1 {
		t.Fatalf("replay stats = %+v, want one accepted and one duplicate", stats)
	}
}

func TestTransportConcurrentBidirectionalTransforms(t *testing.T) {
	ck := bytes.Repeat([]byte{0x01}, 16)
	ik := bytes.Repeat([]byte{0x02}, 16)
	policy, err := NewPolicy(PolicyInput{
		LocalIP:  net.ParseIP("10.0.0.2"),
		RemoteIP: net.ParseIP("10.0.0.1"),
		CK:       ck,
		IK:       ik,
		AuthAlg:  "hmac-sha-1-96",
		EncAlg:   "aes-cbc",
		Mech: SecurityMechanism{
			Alg:   "hmac-sha-1-96",
			EAlg:  "aes-cbc",
			Prot:  "esp",
			Mode:  "trans",
			SPIc:  0x11111111,
			SPIs:  0x22222222,
			PortC: 6054,
			PortS: 6060,
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	transport, err := NewTransport(policy)
	if err != nil {
		t.Fatalf("NewTransport: %v", err)
	}

	const packetCount = 64
	sip := []byte("REGISTER sip:ims.example.org SIP/2.0\r\n\r\n")
	outbound, err := buildOutboundTCPPacket(policy, sip)
	if err != nil {
		t.Fatalf("buildOutboundTCPPacket: %v", err)
	}

	serverFlow := transport.outbound[1]
	inbound := make([][]byte, packetCount)
	for i := range inbound {
		tcpPayload := buildMinimalTCPSegment(policy.FlowS.RemotePort, policy.FlowS.LocalPort, sip)
		esp, err := encapsulateTransport(tcpPayload, serverFlow.outboundSA, ipProtoTCP)
		if err != nil {
			t.Fatalf("encapsulateTransport(%d): %v", i, err)
		}
		inbound[i] = buildIPv4Packet(policy.RemoteIP, policy.LocalIP, ipProtoESP, esp)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, packetCount*2)
	seqCh := make(chan uint32, packetCount)
	for i := 0; i < packetCount; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			encrypted, err := transport.TransformOutbound(outbound)
			if err != nil {
				errCh <- err
				return
			}
			parsed, err := parseIPPacket(encrypted)
			if err != nil {
				errCh <- err
				return
			}
			_, seq, err := parseESPSPISeq(parsed.transportPayload)
			if err != nil {
				errCh <- err
				return
			}
			seqCh <- seq
		}()
		go func(packet []byte) {
			defer wg.Done()
			decrypted, err := transport.TransformInbound(packet)
			if err != nil {
				errCh <- err
				return
			}
			parsed, err := parseIPPacket(decrypted)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Contains(parsed.transportPayload, sip) {
				errCh <- errors.New("decrypted packet is missing SIP payload")
			}
		}(inbound[i])
	}
	wg.Wait()
	close(errCh)
	close(seqCh)
	for err := range errCh {
		t.Errorf("concurrent transform: %v", err)
	}

	sequences := make(map[uint32]struct{}, packetCount)
	for seq := range seqCh {
		if seq == 0 {
			t.Error("outbound ESP sequence number must be non-zero")
		}
		if _, exists := sequences[seq]; exists {
			t.Errorf("duplicate outbound ESP sequence number %d", seq)
		}
		sequences[seq] = struct{}{}
	}
	if len(sequences) != packetCount {
		t.Fatalf("unique outbound sequence count = %d, want %d", len(sequences), packetCount)
	}
	stats := transport.Stats()
	if stats.OutboundPackets != packetCount || stats.InboundPackets != packetCount {
		t.Fatalf("packet stats = outbound:%d inbound:%d, want %d/%d", stats.OutboundPackets, stats.InboundPackets, packetCount, packetCount)
	}
}
