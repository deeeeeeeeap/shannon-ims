package voiceclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type recordingPacketDataplane struct {
	inner chan []byte
	sent  chan []byte
}

func newRecordingPacketDataplane() *recordingPacketDataplane {
	return &recordingPacketDataplane{
		inner: make(chan []byte, 1),
		sent:  make(chan []byte, 1),
	}
}

func TestSWUNetstackUDPReadDeliversMatchingDatagram(t *testing.T) {
	dp := newRecordingPacketDataplane()
	localIP := net.ParseIP("10.0.0.2")
	remoteIP := net.ParseIP("10.0.0.3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	conn, err := netstack.DialContextUDP(context.Background(), localIP, 41234, remoteIP, 5060)
	if err != nil {
		t.Fatalf("DialContextUDP: %v", err)
	}
	defer conn.Close()

	want := []byte("SIP/2.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
	packet, err := buildUDPPacket(remoteIP, localIP, 5060, 41234, want)
	if err != nil {
		t.Fatalf("buildUDPPacket: %v", err)
	}
	dp.inner <- packet
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("UDP Read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("payload = %q, want %q", buf[:n], want)
	}
}

func (d *recordingPacketDataplane) SendInnerPacket(packet []byte) error {
	d.sent <- append([]byte(nil), packet...)
	return nil
}

func (d *recordingPacketDataplane) InnerPackets() <-chan []byte { return d.inner }

func TestSWUNetstackUDPWriteUsesBoundSourcePort(t *testing.T) {
	dp := newRecordingPacketDataplane()
	localIP := net.ParseIP("10.0.0.2")
	remoteIP := net.ParseIP("10.0.0.3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	conn, err := netstack.DialContextUDP(context.Background(), localIP, 41234, remoteIP, 5060)
	if err != nil {
		t.Fatalf("DialContextUDP: %v", err)
	}
	defer conn.Close()

	want := []byte("REGISTER sip:ims.example SIP/2.0\r\n\r\n")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("UDP Write: %v", err)
	}

	select {
	case packet := <-dp.sent:
		payload, source, ok := parseUDPDatagram(packet, remoteIP, 5060)
		if !ok {
			t.Fatalf("outbound packet is not UDP to %s:5060", remoteIP)
		}
		if source.Port != 41234 || !source.IP.Equal(localIP) {
			t.Fatalf("source = %s, want %s:41234", source, localIP)
		}
		if string(payload) != string(want) {
			t.Fatalf("payload = %q, want %q", payload, want)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for outbound UDP packet")
	}
}

func TestSWUNetstackRawIPConnRoutesESPThroughSingleDataplaneConsumer(t *testing.T) {
	dp := newRecordingPacketDataplane()
	localIP := net.ParseIP("10.0.0.2")
	remoteIP := net.ParseIP("10.0.0.3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	raw, err := netstack.DialContextIP(context.Background(), localIP, remoteIP, 50)
	if err != nil {
		t.Fatalf("DialContextIP: %v", err)
	}
	defer raw.Close()

	outbound := buildTestIPv4ProtocolPacket(localIP, remoteIP, 50, []byte("outbound-esp"))
	if _, err := raw.Write(outbound); err != nil {
		t.Fatalf("raw Write: %v", err)
	}
	select {
	case got := <-dp.sent:
		if !bytes.Equal(got, outbound) {
			t.Fatalf("dataplane outbound packet changed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for raw outbound packet")
	}

	inbound := buildTestIPv4ProtocolPacket(remoteIP, localIP, 50, []byte("inbound-esp"))
	dp.inner <- inbound
	if err := raw.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := raw.Read(buf)
	if err != nil {
		t.Fatalf("raw Read: %v", err)
	}
	if !bytes.Equal(buf[:n], inbound) {
		t.Fatalf("raw inbound packet changed")
	}
}

func TestSWUNetstackRawIPConnFragmentsOversizedIPv4Packet(t *testing.T) {
	dp := newRecordingPacketDataplane()
	dp.sent = make(chan []byte, 8)
	localIP := net.ParseIP("10.0.0.2")
	remoteIP := net.ParseIP("10.0.0.3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	raw, err := netstack.DialContextIP(context.Background(), localIP, remoteIP, 50)
	if err != nil {
		t.Fatalf("DialContextIP: %v", err)
	}
	defer raw.Close()

	wantPayload := bytes.Repeat([]byte{0xA5}, 1400)
	outbound := buildTestIPv4ProtocolPacket(localIP, remoteIP, 50, wantPayload)
	if _, err := raw.Write(outbound); err != nil {
		t.Fatalf("raw Write: %v", err)
	}

	fragments := make([][]byte, 0, 2)
	reassembled := make([]byte, len(wantPayload))
	reassembledBytes := 0
	var identification uint16
	for reassembledBytes < len(wantPayload) {
		select {
		case fragment := <-dp.sent:
			if len(fragment) > 1280 {
				t.Fatalf("IPv4 fragment length = %d, want <= 1280", len(fragment))
			}
			if len(fragment) < 20 || fragment[0]>>4 != 4 {
				t.Fatalf("invalid IPv4 fragment")
			}
			headerLen := int(fragment[0]&0x0f) * 4
			if headerLen < 20 || headerLen > len(fragment) {
				t.Fatalf("IPv4 fragment header length = %d", headerLen)
			}
			fragmentID := binary.BigEndian.Uint16(fragment[4:6])
			if len(fragments) == 0 {
				identification = fragmentID
			} else if fragmentID != identification {
				t.Fatalf("fragment identification = %d, want %d", fragmentID, identification)
			}
			flagsOffset := binary.BigEndian.Uint16(fragment[6:8])
			offset := int(flagsOffset&0x1fff) * 8
			fragmentPayload := fragment[headerLen:]
			if offset+len(fragmentPayload) > len(reassembled) {
				t.Fatalf("fragment payload exceeds original packet")
			}
			copy(reassembled[offset:], fragmentPayload)
			reassembledBytes += len(fragmentPayload)
			fragments = append(fragments, fragment)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for IPv4 fragments")
		}
	}
	if len(fragments) < 2 {
		t.Fatalf("fragment count = %d, want at least 2", len(fragments))
	}
	if !bytes.Equal(reassembled, wantPayload) {
		t.Fatal("reassembled IPv4 payload differs from original")
	}
}

func buildTestIPv4ProtocolPacket(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	return packet
}
