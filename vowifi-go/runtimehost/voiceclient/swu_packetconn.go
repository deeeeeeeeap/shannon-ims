package voiceclient

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// PacketDataplane is the pure userspace SWu dataplane used by WiFi Calling.
// Packets are inner IPv4/IPv6 packets, before ESP encapsulation.
type PacketDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

type swuPacketConn struct {
	localIP   net.IP
	localPort int
	dp        PacketDataplane
	rx        chan udpDatagram
	closed    chan struct{}
	once      sync.Once
}

type udpDatagram struct {
	payload []byte
	addr    *net.UDPAddr
}

func newSWUPacketConn(localIP net.IP, localPort int, dp PacketDataplane) *swuPacketConn {
	c := &swuPacketConn{
		localIP:   append(net.IP(nil), localIP...),
		localPort: localPort,
		dp:        dp,
		rx:        make(chan udpDatagram, 128),
		closed:    make(chan struct{}),
	}
	go c.readLoop()
	return c
}

func (c *swuPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case d := <-c.rx:
		n := copy(b, d.payload)
		return n, d.addr, nil
	}
}

func (c *swuPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, err := toUDPAddr(addr)
	if err != nil {
		return 0, err
	}
	packet, err := buildUDPPacket(c.localIP, udpAddr.IP, c.localPort, udpAddr.Port, b)
	if err != nil {
		return 0, err
	}
	if err := c.dp.SendInnerPacket(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *swuPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *swuPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: append(net.IP(nil), c.localIP...), Port: c.localPort}
}

func (c *swuPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *swuPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *swuPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *swuPacketConn) readLoop() {
	for {
		select {
		case <-c.closed:
			return
		case packet, ok := <-c.dp.InnerPackets():
			if !ok {
				return
			}
			payload, addr, ok := parseUDPDatagram(packet, c.localIP, c.localPort)
			if !ok {
				continue
			}
			select {
			case <-c.closed:
				return
			case c.rx <- udpDatagram{payload: payload, addr: addr}:
			default:
			}
		}
	}
}

func toUDPAddr(addr net.Addr) (*net.UDPAddr, error) {
	if addr == nil {
		return nil, errors.New("voiceclient: nil UDP addr")
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		if ua.IP == nil || ua.Port <= 0 {
			return nil, fmt.Errorf("voiceclient: invalid UDP addr %q", addr.String())
		}
		return ua, nil
	}
	ua, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return nil, err
	}
	return ua, nil
}

func buildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) ([]byte, error) {
	if srcIP == nil || dstIP == nil {
		return nil, errors.New("voiceclient: source and destination IP are required")
	}
	if src4, dst4 := srcIP.To4(), dstIP.To4(); src4 != nil && dst4 != nil {
		return buildIPv4UDPPacket(src4, dst4, srcPort, dstPort, payload), nil
	}
	src16, dst16 := srcIP.To16(), dstIP.To16()
	if src16 == nil || dst16 == nil {
		return nil, fmt.Errorf("voiceclient: invalid IP pair %s -> %s", srcIP, dstIP)
	}
	return buildIPv6UDPPacket(src16, dst16, srcPort, dstPort, payload), nil
}

func buildIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	writeUDP(packet[20:], srcIP.To4(), dstIP.To4(), srcPort, dstPort, payload, false)
	return packet
}

func buildIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	payloadLen := 8 + len(payload)
	packet := make([]byte, 40+payloadLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(payloadLen))
	packet[6] = 17
	packet[7] = 64
	copy(packet[8:24], srcIP.To16())
	copy(packet[24:40], dstIP.To16())
	writeUDP(packet[40:], srcIP.To16(), dstIP.To16(), srcPort, dstPort, payload, true)
	return packet
}

func writeUDP(udp []byte, srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte, ipv6 bool) {
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	sum := udpChecksum(srcIP, dstIP, udp, ipv6)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
}

func parseUDPDatagram(packet []byte, localIP net.IP, localPort int) ([]byte, *net.UDPAddr, bool) {
	if len(packet) == 0 {
		return nil, nil, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 28 {
			return nil, nil, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl+8 || packet[9] != 17 {
			return nil, nil, false
		}
		dst := net.IP(packet[16:20])
		if !dst.Equal(localIP.To4()) {
			return nil, nil, false
		}
		return parseUDPAt(packet, ihl, net.IP(packet[12:16]), localPort)
	case 6:
		if len(packet) < 48 || packet[6] != 17 {
			return nil, nil, false
		}
		dst := net.IP(packet[24:40])
		if !dst.Equal(localIP.To16()) {
			return nil, nil, false
		}
		return parseUDPAt(packet, 40, net.IP(packet[8:24]), localPort)
	default:
		return nil, nil, false
	}
}

func parseUDPAt(packet []byte, off int, srcIP net.IP, localPort int) ([]byte, *net.UDPAddr, bool) {
	if len(packet) < off+8 {
		return nil, nil, false
	}
	srcPort := int(binary.BigEndian.Uint16(packet[off : off+2]))
	dstPort := int(binary.BigEndian.Uint16(packet[off+2 : off+4]))
	udpLen := int(binary.BigEndian.Uint16(packet[off+4 : off+6]))
	if dstPort != localPort || udpLen < 8 || len(packet) < off+udpLen {
		return nil, nil, false
	}
	payload := append([]byte(nil), packet[off+8:off+udpLen]...)
	return payload, &net.UDPAddr{IP: append(net.IP(nil), srcIP...), Port: srcPort}, true
}

func udpChecksum(srcIP, dstIP net.IP, udp []byte, ipv6 bool) uint16 {
	pseudoLen := 12
	if ipv6 {
		pseudoLen = 40
	}
	pseudo := make([]byte, 0, pseudoLen+len(udp))
	pseudo = append(pseudo, srcIP...)
	pseudo = append(pseudo, dstIP...)
	if ipv6 {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(udp)))
		pseudo = append(pseudo, l[:]...)
		pseudo = append(pseudo, 0, 0, 0, 17)
	} else {
		pseudo = append(pseudo, 0, 17)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(udp)))
		pseudo = append(pseudo, l[:]...)
	}
	pseudo = append(pseudo, udp...)
	return checksum(pseudo)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) > 1 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
