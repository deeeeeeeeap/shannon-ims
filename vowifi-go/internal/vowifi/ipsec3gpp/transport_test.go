package ipsec3gpp

import (
	"bytes"
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
