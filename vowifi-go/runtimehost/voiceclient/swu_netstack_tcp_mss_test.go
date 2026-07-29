package voiceclient

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

const testSWUTCPMSSCap = 1024

func TestSWUNetstackTCPAdvertisesConservativeMSS(t *testing.T) {
	dp := newRecordingPacketDataplane()
	dp.inner = make(chan []byte, 16)
	dp.sent = make(chan []byte, 16)
	localIP := net.ParseIP("2001:db8::2")
	remoteIP := net.ParseIP("2001:db8::3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	ctx, cancel := context.WithCancel(context.Background())
	dialDone := make(chan error, 1)
	go func() {
		conn, dialErr := netstack.DialContextTCP(ctx, localIP, 41234, remoteIP, 5060)
		if conn != nil {
			_ = conn.Close()
		}
		dialDone <- dialErr
	}()

	syn := receiveSWUTCPPacket(t, dp.sent)
	parsed := parseSyntheticSWUTCPPacket(t, syn)
	if parsed.flags != 0x02 {
		t.Fatalf("first TCP flags = %#x, want SYN", parsed.flags)
	}
	if parsed.mss != testSWUTCPMSSCap {
		t.Fatalf("advertised MSS = %d, want %d", parsed.mss, testSWUTCPMSSCap)
	}

	cancel()
	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("TCP dial did not join after cancellation")
	}
}

func TestSWUNetstackTCPClampsPeerMSSBeforeSendingApplicationData(t *testing.T) {
	dp := newRecordingPacketDataplane()
	dp.inner = make(chan []byte, 16)
	dp.sent = make(chan []byte, 32)
	localIP := net.ParseIP("2001:db8::2")
	remoteIP := net.ParseIP("2001:db8::3")
	netstack, err := newSWUNetstack(localIP, dp)
	if err != nil {
		t.Fatalf("newSWUNetstack: %v", err)
	}
	defer netstack.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type dialResult struct {
		conn net.Conn
		err  error
	}
	dialDone := make(chan dialResult, 1)
	go func() {
		conn, dialErr := netstack.DialContextTCP(ctx, localIP, 41234, remoteIP, 5060)
		dialDone <- dialResult{conn: conn, err: dialErr}
	}()

	synPacket := receiveSWUTCPPacket(t, dp.sent)
	syn := parseSyntheticSWUTCPPacket(t, synPacket)
	if syn.flags != 0x02 {
		t.Fatalf("first TCP flags = %#x, want SYN", syn.flags)
	}
	peerAdvertisedMSS := 1440
	synAck := buildSyntheticIPv6TCPSYNACK(
		t, remoteIP, localIP, 5060, syn.sourcePort, 9000, syn.sequence+1, peerAdvertisedMSS,
	)
	dp.inner <- synAck

	var dial dialResult
	select {
	case dial = <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("TCP dial did not complete after SYN-ACK")
	}
	if dial.err != nil {
		t.Fatalf("DialContextTCP: %v", dial.err)
	}
	defer dial.conn.Close()

	payload := make([]byte, 1300)
	if _, err := dial.conn.Write(payload); err != nil {
		t.Fatalf("TCP Write: %v", err)
	}

	totalPayload := 0
	maxPayload := 0
	dataSegments := 0
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for totalPayload < len(payload) {
		select {
		case packet := <-dp.sent:
			segment := parseSyntheticSWUTCPPacket(t, packet)
			if segment.payloadLen == 0 {
				continue
			}
			dataSegments++
			totalPayload += segment.payloadLen
			if segment.payloadLen > maxPayload {
				maxPayload = segment.payloadLen
			}
		case <-deadline.C:
			t.Fatalf("captured %d/%d TCP payload bytes", totalPayload, len(payload))
		}
	}
	if maxPayload > testSWUTCPMSSCap {
		t.Fatalf("largest TCP payload = %d, want <= %d", maxPayload, testSWUTCPMSSCap)
	}
	if dataSegments < 2 {
		t.Fatalf("TCP data segment count = %d, want at least 2", dataSegments)
	}
	if got := binary.BigEndian.Uint16(synAck[62:64]); got != uint16(peerAdvertisedMSS) {
		t.Fatalf("source SYN-ACK MSS was modified: got %d, want %d", got, peerAdvertisedMSS)
	}
}

func TestClampSWUTCPHandshakeMSSIPv4UsesCopyAndValidChecksum(t *testing.T) {
	sourceIP := net.ParseIP("192.0.2.3")
	destinationIP := net.ParseIP("192.0.2.2")
	packet := buildSyntheticIPv4TCPSYNACK(
		t, sourceIP, destinationIP, 5060, 41234, 9000, 7000, 1440,
	)
	original := append([]byte(nil), packet...)

	clamped := clampSWUTCPHandshakeMSS(packet, testSWUTCPMSSCap)
	if bytes.Equal(clamped, packet) {
		t.Fatal("oversized IPv4 peer MSS was not clamped")
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("source IPv4 SYN-ACK was modified")
	}
	if got := binary.BigEndian.Uint16(clamped[42:44]); got != testSWUTCPMSSCap {
		t.Fatalf("clamped IPv4 MSS = %d, want %d", got, testSWUTCPMSSCap)
	}
	wantChecksum := independentSyntheticIPv4TCPChecksum(clamped, true)
	if got := binary.BigEndian.Uint16(clamped[36:38]); got != wantChecksum {
		t.Fatalf("clamped IPv4 TCP checksum is invalid")
	}
}

type syntheticSWUTCPPacket struct {
	sourcePort uint16
	sequence   uint32
	flags      byte
	mss        int
	payloadLen int
}

func receiveSWUTCPPacket(t *testing.T, packets <-chan []byte) []byte {
	t.Helper()
	select {
	case packet := <-packets:
		return packet
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SWu TCP packet")
		return nil
	}
}

func parseSyntheticSWUTCPPacket(t *testing.T, packet []byte) syntheticSWUTCPPacket {
	t.Helper()
	if len(packet) < 60 || packet[0]>>4 != 6 || packet[6] != 6 {
		t.Fatal("packet is not a complete IPv6 TCP segment")
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLength != len(packet)-40 {
		t.Fatalf("IPv6 payload length = %d, packet carries %d", payloadLength, len(packet)-40)
	}
	segment := packet[40:]
	headerLength := int(segment[12]>>4) * 4
	if headerLength < 20 || headerLength > len(segment) {
		t.Fatalf("TCP header length = %d", headerLength)
	}
	parsed := syntheticSWUTCPPacket{
		sourcePort: binary.BigEndian.Uint16(segment[0:2]),
		sequence:   binary.BigEndian.Uint32(segment[4:8]),
		flags:      segment[13],
		payloadLen: len(segment) - headerLength,
	}
	options := segment[20:headerLength]
	for i := 0; i < len(options); {
		switch options[i] {
		case 0:
			i = len(options)
		case 1:
			i++
		default:
			if i+1 >= len(options) {
				t.Fatal("truncated TCP option")
			}
			optionLength := int(options[i+1])
			if optionLength < 2 || i+optionLength > len(options) {
				t.Fatal("invalid TCP option length")
			}
			if options[i] == 2 && optionLength == 4 {
				parsed.mss = int(binary.BigEndian.Uint16(options[i+2 : i+4]))
			}
			i += optionLength
		}
	}
	return parsed
}

func buildSyntheticIPv6TCPSYNACK(
	t *testing.T,
	sourceIP, destinationIP net.IP,
	sourcePort, destinationPort uint16,
	sequence, acknowledgement uint32,
	mss int,
) []byte {
	t.Helper()
	packet := make([]byte, 40+24)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 24)
	packet[6] = 6
	packet[7] = 64
	copy(packet[8:24], sourceIP.To16())
	copy(packet[24:40], destinationIP.To16())
	segment := packet[40:]
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	binary.BigEndian.PutUint32(segment[8:12], acknowledgement)
	segment[12] = 6 << 4
	segment[13] = 0x12
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	segment[20], segment[21] = 2, 4
	binary.BigEndian.PutUint16(segment[22:24], uint16(mss))
	binary.BigEndian.PutUint16(segment[16:18], independentSyntheticTCPChecksum(packet))
	return packet
}

func buildSyntheticIPv4TCPSYNACK(
	t *testing.T,
	sourceIP, destinationIP net.IP,
	sourcePort, destinationPort uint16,
	sequence, acknowledgement uint32,
	mss int,
) []byte {
	t.Helper()
	packet := make([]byte, 20+24)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:16], sourceIP.To4())
	copy(packet[16:20], destinationIP.To4())
	segment := packet[20:]
	binary.BigEndian.PutUint16(segment[0:2], sourcePort)
	binary.BigEndian.PutUint16(segment[2:4], destinationPort)
	binary.BigEndian.PutUint32(segment[4:8], sequence)
	binary.BigEndian.PutUint32(segment[8:12], acknowledgement)
	segment[12] = 6 << 4
	segment[13] = 0x12
	binary.BigEndian.PutUint16(segment[14:16], 65535)
	segment[20], segment[21] = 2, 4
	binary.BigEndian.PutUint16(segment[22:24], uint16(mss))
	binary.BigEndian.PutUint16(segment[16:18], independentSyntheticIPv4TCPChecksum(packet, false))
	binary.BigEndian.PutUint16(packet[10:12], independentSyntheticChecksum(packet[:20]))
	return packet
}

func independentSyntheticTCPChecksum(packet []byte) uint16 {
	segment := packet[40:]
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
	add(packet[8:24])
	add(packet[24:40])
	length := []byte{0, 0, 0, byte(len(segment))}
	add(length)
	add([]byte{0, 0, 0, 6})
	add(segment)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func independentSyntheticIPv4TCPChecksum(packet []byte, clearChecksum bool) uint16 {
	segment := append([]byte(nil), packet[20:]...)
	if clearChecksum {
		segment[16], segment[17] = 0, 0
	}
	var pseudo []byte
	pseudo = append(pseudo, packet[12:16]...)
	pseudo = append(pseudo, packet[16:20]...)
	pseudo = append(pseudo, 0, 6)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(segment)))
	pseudo = append(pseudo, length[:]...)
	pseudo = append(pseudo, segment...)
	return independentSyntheticChecksum(pseudo)
}

func independentSyntheticChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
