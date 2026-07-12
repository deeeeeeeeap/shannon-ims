package voiceclient

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	swuRawIPQueueDepth = 64
	swuRawIPMTU        = 1280
)

var swuRawIPv4FragmentID atomic.Uint32

type swuRawIPConn struct {
	owner    *swuNetstack
	localIP  net.IP
	remoteIP net.IP
	protocol uint8
	rx       chan []byte
	closed   chan struct{}
	once     sync.Once

	deadlineMu    sync.RWMutex
	readDeadline  time.Time
	writeDeadline time.Time
}

type rawIPPacketMetadata struct {
	src      net.IP
	dst      net.IP
	protocol uint8
}

func (n *swuNetstack) DialContextIP(ctx context.Context, localIP net.IP, remoteIP net.IP, protocol uint8) (net.Conn, error) {
	if n == nil || n.dp == nil {
		return nil, errors.New("voiceclient: SWu raw IP dataplane unavailable")
	}
	if protocol == 0 {
		return nil, errors.New("voiceclient: raw IP protocol is required")
	}
	if localIP == nil || remoteIP == nil {
		return nil, errors.New("voiceclient: raw IP endpoints are required")
	}
	if (localIP.To4() == nil) != (remoteIP.To4() == nil) {
		return nil, fmt.Errorf("voiceclient: raw IP family mismatch %s -> %s", localIP, remoteIP)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.closed:
		return nil, net.ErrClosed
	default:
	}

	conn := &swuRawIPConn{
		owner:    n,
		localIP:  canonicalNetIP(localIP),
		remoteIP: canonicalNetIP(remoteIP),
		protocol: protocol,
		rx:       make(chan []byte, swuRawIPQueueDepth),
		closed:   make(chan struct{}),
	}
	n.rawMu.Lock()
	n.rawConn[conn] = struct{}{}
	n.rawMu.Unlock()
	return conn, nil
}

func (n *swuNetstack) dispatchRawIPPacket(packet []byte) bool {
	metadata, ok := parseRawIPPacketMetadata(packet)
	if !ok {
		return false
	}

	delivered := false
	n.rawMu.RLock()
	for conn := range n.rawConn {
		if conn.matchesInbound(metadata) {
			conn.deliver(packet)
			delivered = true
		}
	}
	n.rawMu.RUnlock()
	return delivered
}

func (n *swuNetstack) unregisterRawIPConn(conn *swuRawIPConn) {
	if n == nil || conn == nil {
		return
	}
	n.rawMu.Lock()
	delete(n.rawConn, conn)
	n.rawMu.Unlock()
}

func (c *swuRawIPConn) Read(p []byte) (int, error) {
	if c == nil || c.owner == nil {
		return 0, net.ErrClosed
	}
	deadline := c.deadlines().read
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}

	var timer *time.Timer
	var deadlineC <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		deadlineC = timer.C
		defer timer.Stop()
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.owner.closed:
		return 0, net.ErrClosed
	case <-deadlineC:
		return 0, os.ErrDeadlineExceeded
	case packet := <-c.rx:
		return copy(p, packet), nil
	}
}

func (c *swuRawIPConn) Write(p []byte) (int, error) {
	if c == nil || c.owner == nil || c.owner.dp == nil {
		return 0, net.ErrClosed
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.owner.closed:
		return 0, net.ErrClosed
	default:
	}
	deadline := c.deadlines().write
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	metadata, ok := parseRawIPPacketMetadata(p)
	if !ok || metadata.protocol != c.protocol || !metadata.src.Equal(c.localIP) || !metadata.dst.Equal(c.remoteIP) {
		return 0, errors.New("voiceclient: raw IP packet does not match connection")
	}
	packets, err := fragmentRawIPv4Packet(p, swuRawIPMTU)
	if err != nil {
		return 0, err
	}
	for _, packet := range packets {
		if err := c.owner.dp.SendInnerPacket(packet); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func fragmentRawIPv4Packet(packet []byte, mtu int) ([][]byte, error) {
	if len(packet) <= mtu || len(packet) == 0 || packet[0]>>4 != 4 {
		return [][]byte{append([]byte(nil), packet...)}, nil
	}
	if mtu < 28 || len(packet) < 20 {
		return nil, errors.New("voiceclient: invalid raw IPv4 fragmentation input")
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(packet) || headerLen >= mtu {
		return nil, errors.New("voiceclient: invalid raw IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < headerLen || totalLen > len(packet) {
		return nil, errors.New("voiceclient: invalid raw IPv4 total length")
	}
	flagsOffset := binary.BigEndian.Uint16(packet[6:8])
	if flagsOffset&0x3fff != 0 {
		return nil, errors.New("voiceclient: raw IPv4 packet is already fragmented")
	}
	maxPayloadLen := ((mtu - headerLen) / 8) * 8
	if maxPayloadLen <= 0 {
		return nil, errors.New("voiceclient: raw IPv4 MTU leaves no fragment payload")
	}
	payload := packet[headerLen:totalLen]
	identification := binary.BigEndian.Uint16(packet[4:6])
	if identification == 0 {
		identification = uint16(swuRawIPv4FragmentID.Add(1))
		if identification == 0 {
			identification = uint16(swuRawIPv4FragmentID.Add(1))
		}
	}
	fragments := make([][]byte, 0, (len(payload)+maxPayloadLen-1)/maxPayloadLen)
	for offset := 0; offset < len(payload); {
		remaining := len(payload) - offset
		fragmentPayloadLen := remaining
		if fragmentPayloadLen > maxPayloadLen {
			fragmentPayloadLen = maxPayloadLen
		}
		moreFragments := offset+fragmentPayloadLen < len(payload)
		fragment := make([]byte, headerLen+fragmentPayloadLen)
		copy(fragment[:headerLen], packet[:headerLen])
		copy(fragment[headerLen:], payload[offset:offset+fragmentPayloadLen])
		binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
		binary.BigEndian.PutUint16(fragment[4:6], identification)
		fragmentOffset := uint16(offset/8) & 0x1fff
		if moreFragments {
			fragmentOffset |= 0x2000
		}
		binary.BigEndian.PutUint16(fragment[6:8], fragmentOffset)
		fragment[10], fragment[11] = 0, 0
		binary.BigEndian.PutUint16(fragment[10:12], checksum(fragment[:headerLen]))
		fragments = append(fragments, fragment)
		offset += fragmentPayloadLen
	}
	return fragments, nil
}

func (c *swuRawIPConn) Close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		if c.owner != nil {
			c.owner.unregisterRawIPConn(c)
		}
		close(c.closed)
	})
	return nil
}

func (c *swuRawIPConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: append(net.IP(nil), c.localIP...)}
}

func (c *swuRawIPConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: append(net.IP(nil), c.remoteIP...)}
}

func (c *swuRawIPConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *swuRawIPConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *swuRawIPConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *swuRawIPConn) deadlines() struct{ read, write time.Time } {
	c.deadlineMu.RLock()
	defer c.deadlineMu.RUnlock()
	return struct{ read, write time.Time }{read: c.readDeadline, write: c.writeDeadline}
}

func (c *swuRawIPConn) matchesInbound(metadata rawIPPacketMetadata) bool {
	if c == nil {
		return false
	}
	return metadata.protocol == c.protocol && metadata.src.Equal(c.remoteIP) && metadata.dst.Equal(c.localIP)
}

func (c *swuRawIPConn) deliver(packet []byte) {
	select {
	case <-c.closed:
		return
	case c.rx <- append([]byte(nil), packet...):
	default:
	}
}

func parseRawIPPacketMetadata(packet []byte) (rawIPPacketMetadata, bool) {
	if len(packet) < 1 {
		return rawIPPacketMetadata{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return rawIPPacketMetadata{}, false
		}
		ihl := int(packet[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if ihl < 20 || totalLen < ihl || totalLen > len(packet) {
			return rawIPPacketMetadata{}, false
		}
		return rawIPPacketMetadata{
			src:      append(net.IP(nil), packet[12:16]...),
			dst:      append(net.IP(nil), packet[16:20]...),
			protocol: packet[9],
		}, true
	case 6:
		if len(packet) < 40 {
			return rawIPPacketMetadata{}, false
		}
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if 40+payloadLen > len(packet) {
			return rawIPPacketMetadata{}, false
		}
		return rawIPPacketMetadata{
			src:      append(net.IP(nil), packet[8:24]...),
			dst:      append(net.IP(nil), packet[24:40]...),
			protocol: packet[6],
		}, true
	default:
		return rawIPPacketMetadata{}, false
	}
}

func canonicalNetIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...)
	}
	return append(net.IP(nil), ip.To16()...)
}
