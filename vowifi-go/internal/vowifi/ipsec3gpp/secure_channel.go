package ipsec3gpp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SecureChannelConn wraps an IP carrier with userspace ESP transport-mode transforms.
type SecureChannelConn struct {
	conn       net.Conn
	transport  *Transport
	policy     Policy
	protocol   uint8
	packetMode bool
	readBuf    []byte
	mu         sync.Mutex
	writeMu    sync.Mutex
}

// WrapSecureChannel wraps conn with outbound ESP transforms for SIP-over-TCP.
func WrapSecureChannel(conn net.Conn, transport *Transport, policy Policy) *SecureChannelConn {
	return &SecureChannelConn{
		conn:      conn,
		transport: transport,
		policy:    policy,
		protocol:  ipProtoTCP,
	}
}

// WrapSecureChannelUDP wraps a packet-mode raw IP connection with ESP
// transport-mode transforms for SIP-over-UDP.
func WrapSecureChannelUDP(conn net.Conn, transport *Transport, policy Policy) *SecureChannelConn {
	return &SecureChannelConn{
		conn:       conn,
		transport:  transport,
		policy:     policy,
		protocol:   ipProtoUDP,
		packetMode: true,
	}
}

func (c *SecureChannelConn) Read(p []byte) (int, error) {
	if c == nil || c.conn == nil {
		return 0, errors.New("ipsec3gpp: secure channel is not ready")
	}
	for {
		payload, err := c.readSIPPayload()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			continue
		}
		n := copy(p, payload)
		if n < len(payload) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf, payload[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	}
}

func (c *SecureChannelConn) Write(p []byte) (int, error) {
	return c.writeFlow(p, c.policy.FlowC)
}

// WriteServerFlow sends a UE response on the port-s -> P-CSCF port-c flow.
func (c *SecureChannelConn) WriteServerFlow(p []byte) (int, error) {
	if c == nil || c.protocol != ipProtoUDP {
		return 0, errors.New("ipsec3gpp: server flow requires UDP secure channel")
	}
	return c.writeFlow(p, c.policy.FlowS)
}

func (c *SecureChannelConn) writeFlow(p []byte, flow Flow) (int, error) {
	if c == nil || c.conn == nil || c.transport == nil {
		return 0, errors.New("ipsec3gpp: secure channel is not ready")
	}
	packet, err := c.buildOutboundPacket(p, flow)
	if err != nil {
		return 0, err
	}
	encrypted, err := c.transport.TransformOutbound(packet)
	if err != nil {
		return 0, err
	}
	c.writeMu.Lock()
	_, err = c.conn.Write(encrypted)
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *SecureChannelConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *SecureChannelConn) LocalAddr() net.Addr {
	if c != nil && c.protocol == ipProtoUDP {
		return &net.UDPAddr{IP: append(net.IP(nil), c.policy.LocalIP...), Port: c.policy.FlowC.LocalPort}
	}
	return c.conn.LocalAddr()
}

func (c *SecureChannelConn) RemoteAddr() net.Addr {
	if c != nil && c.protocol == ipProtoUDP {
		return &net.UDPAddr{IP: append(net.IP(nil), c.policy.RemoteIP...), Port: c.policy.FlowC.RemotePort}
	}
	return c.conn.RemoteAddr()
}

func (c *SecureChannelConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *SecureChannelConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *SecureChannelConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// PacketMode reports whether the carrier exchanges one complete ESP/IP packet
// per read/write instead of streaming packets through another TCP connection.
func (c *SecureChannelConn) PacketMode() bool { return c != nil && c.packetMode }

func (c *SecureChannelConn) readSIPPayload() ([]byte, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		out := c.readBuf
		c.readBuf = nil
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	for {
		ipPacket, err := c.readIPPacket()
		if err != nil {
			return nil, err
		}
		plain, err := c.transport.TransformInbound(ipPacket)
		if err != nil {
			return nil, err
		}
		parsed, err := parseIPPacket(plain)
		if err != nil {
			return nil, err
		}
		if parsed.nextHeader != c.protocol {
			continue
		}
		switch c.protocol {
		case ipProtoUDP:
			return parseUDPPayload(parsed.transportPayload)
		case ipProtoTCP:
			if len(parsed.transportPayload) < 20 {
				return nil, errors.New("ipsec3gpp: TCP segment too short")
			}
			headerLen := int(parsed.transportPayload[12]>>4) * 4
			if headerLen < 20 || headerLen > len(parsed.transportPayload) {
				return nil, errors.New("ipsec3gpp: invalid TCP header length")
			}
			return parsed.transportPayload[headerLen:], nil
		default:
			return nil, fmt.Errorf("ipsec3gpp: unsupported secure channel protocol %d", c.protocol)
		}
	}
}

func (c *SecureChannelConn) readIPPacket() ([]byte, error) {
	if c.packetMode {
		packet := make([]byte, 64*1024)
		n, err := c.conn.Read(packet)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return packet[:n], nil
	}
	header := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}
	version := header[0] >> 4
	switch version {
	case 4:
		rest := make([]byte, 19)
		if _, err := io.ReadFull(c.conn, rest); err != nil {
			return nil, err
		}
		packet := append(header, rest...)
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if totalLen < 20 {
			return nil, errors.New("ipsec3gpp: invalid IPv4 total length")
		}
		if totalLen > 20 {
			extra := make([]byte, totalLen-20)
			if _, err := io.ReadFull(c.conn, extra); err != nil {
				return nil, err
			}
			packet = append(packet, extra...)
		}
		return packet, nil
	case 6:
		rest := make([]byte, 39)
		if _, err := io.ReadFull(c.conn, rest); err != nil {
			return nil, err
		}
		packet := append(header, rest...)
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if payloadLen > 0 {
			extra := make([]byte, payloadLen)
			if _, err := io.ReadFull(c.conn, extra); err != nil {
				return nil, err
			}
			packet = append(packet, extra...)
		}
		return packet, nil
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported IP version %d", version)
	}
}

func (c *SecureChannelConn) buildOutboundPacket(payload []byte, flow Flow) ([]byte, error) {
	switch c.protocol {
	case ipProtoUDP:
		return buildOutboundUDPPacketForFlow(c.policy, flow, payload)
	case ipProtoTCP:
		return buildOutboundTCPPacket(c.policy, payload)
	default:
		return nil, fmt.Errorf("ipsec3gpp: unsupported secure channel protocol %d", c.protocol)
	}
}

func buildOutboundTCPPacket(policy Policy, sipPayload []byte) ([]byte, error) {
	tcpSegment := buildMinimalTCPSegment(policy.FlowC.LocalPort, policy.FlowC.RemotePort, sipPayload)
	if len(policy.LocalIP) == 4 {
		return buildIPv4Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	if len(policy.LocalIP) == 16 {
		return buildIPv6Packet(policy.LocalIP, policy.RemoteIP, ipProtoTCP, tcpSegment), nil
	}
	return nil, errors.New("ipsec3gpp: unsupported local IP length")
}

func buildMinimalTCPSegment(srcPort, dstPort int, payload []byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:8], 1)
	binary.BigEndian.PutUint32(hdr[8:12], 1)
	hdr[12] = 0x50
	hdr[13] = 0x18 // PSH+ACK
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	return append(hdr, payload...)
}

func buildOutboundUDPPacket(policy Policy, sipPayload []byte) ([]byte, error) {
	return buildOutboundUDPPacketForFlow(policy, policy.FlowC, sipPayload)
}

func buildOutboundUDPPacketForFlow(policy Policy, flow Flow, sipPayload []byte) ([]byte, error) {
	udp, err := buildUDPSegment(policy.LocalIP, policy.RemoteIP, flow.LocalPort, flow.RemotePort, sipPayload)
	if err != nil {
		return nil, err
	}
	if len(policy.LocalIP) == 4 {
		return buildIPv4Packet(policy.LocalIP, policy.RemoteIP, ipProtoUDP, udp), nil
	}
	if len(policy.LocalIP) == 16 {
		return buildIPv6Packet(policy.LocalIP, policy.RemoteIP, ipProtoUDP, udp), nil
	}
	return nil, errors.New("ipsec3gpp: unsupported local IP length")
}

func buildUDPSegment(srcIP, dstIP []byte, srcPort, dstPort int, payload []byte) ([]byte, error) {
	if srcPort <= 0 || dstPort <= 0 || srcPort > 0xffff || dstPort > 0xffff {
		return nil, errors.New("ipsec3gpp: invalid UDP port")
	}
	if len(srcIP) != len(dstIP) || (len(srcIP) != 4 && len(srcIP) != 16) {
		return nil, errors.New("ipsec3gpp: invalid UDP IP pair")
	}
	udpLen := 8 + len(payload)
	if udpLen > 0xffff {
		return nil, errors.New("ipsec3gpp: UDP payload too large")
	}
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	checksum := udpTransportChecksum(srcIP, dstIP, udp)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return udp, nil
}

func parseUDPPayload(udp []byte) ([]byte, error) {
	if len(udp) < 8 {
		return nil, errors.New("ipsec3gpp: UDP datagram too short")
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return nil, errors.New("ipsec3gpp: invalid UDP length")
	}
	return udp[8:udpLen], nil
}

func udpTransportChecksum(srcIP, dstIP, udp []byte) uint16 {
	pseudo := make([]byte, 0, len(srcIP)+len(dstIP)+8+len(udp))
	pseudo = append(pseudo, srcIP...)
	pseudo = append(pseudo, dstIP...)
	if len(srcIP) == 16 {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(udp)))
		pseudo = append(pseudo, length[:]...)
		pseudo = append(pseudo, 0, 0, 0, ipProtoUDP)
	} else {
		pseudo = append(pseudo, 0, ipProtoUDP)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(udp)))
		pseudo = append(pseudo, length[:]...)
	}
	pseudo = append(pseudo, udp...)
	return internetChecksum(pseudo)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
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

func buildIPv4Packet(src, dst []byte, proto uint8, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	total := uint16(20 + len(payload))
	binary.BigEndian.PutUint16(hdr[2:4], total)
	hdr[8] = 64
	hdr[9] = proto
	copy(hdr[12:16], src)
	copy(hdr[16:20], dst)
	updateIPv4HeaderChecksum(hdr)
	return append(hdr, payload...)
}

func buildIPv6Packet(src, dst []byte, nextHeader uint8, payload []byte) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(payload)))
	hdr[6] = nextHeader
	copy(hdr[8:24], src)
	copy(hdr[24:40], dst)
	return append(hdr, payload...)
}
