package voiceclient

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/1239t/swu-go/pkg/logger"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	gtcp "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	gudp "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const swuNetstackNICID = 1
const swuNetstackMTU = 1500

// SWUTCPDialer opens TCP connections through the userspace SWu dataplane.
type SWUTCPDialer interface {
	DialContextTCP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error)
	DialContextUDP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error)
	ListenContextTCP(ctx context.Context, localIP net.IP, localPort int) (net.Listener, error)
	ListenContextUDP(ctx context.Context, localIP net.IP, localPort int) (net.PacketConn, error)
	Close() error
}

// SWURawIPDialer exposes packet-mode IP protocols (notably ESP) through the
// same SWu netstack that owns the dataplane receive loop.
type SWURawIPDialer interface {
	DialContextIP(ctx context.Context, localIP net.IP, remoteIP net.IP, protocol uint8) (net.Conn, error)
}

// NewSWUTCPDialer returns a dialer bound to the tunnel virtual IP.
func NewSWUTCPDialer(localIP net.IP, dp PacketDataplane) (SWUTCPDialer, error) {
	return newSWUNetstack(localIP, dp)
}

type swuNetstack struct {
	dp      PacketDataplane
	linkEP  *channel.Endpoint
	stack   *stack.Stack
	localIP net.IP
	rawMu   sync.RWMutex
	rawConn map[*swuRawIPConn]struct{}

	closeOnce sync.Once
	closed    chan struct{}
}

func newSWUNetstack(localIP net.IP, dp PacketDataplane) (*swuNetstack, error) {
	if dp == nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack requires dataplane")
	}
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack requires local IP")
	}

	ns := &swuNetstack{
		dp:      dp,
		linkEP:  channel.New(512, swuNetstackMTU, ""),
		localIP: append(net.IP(nil), localIP...),
		rawConn: make(map[*swuRawIPConn]struct{}),
		closed:  make(chan struct{}),
	}

	ns.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{gtcp.NewProtocol, gudp.NewProtocol},
	})
	if err := ns.stack.CreateNIC(swuNetstackNICID, ns.linkEP); err != nil {
		return nil, fmt.Errorf("voiceclient: SWu netstack create NIC: %v", err)
	}

	if err := ns.addLocalAddress(); err != nil {
		return nil, err
	}
	ns.stack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         swuNetstackNICID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         swuNetstackNICID,
		},
	})

	go ns.inboundLoop()
	go ns.outboundLoop()
	return ns, nil
}

func (n *swuNetstack) Close() error {
	n.closeOnce.Do(func() {
		close(n.closed)
		n.linkEP.Close()
		n.stack.Close()
		n.stack.Wait()
	})
	return nil
}

func (n *swuNetstack) DialContextTCP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error) {
	if remoteIP == nil {
		return nil, fmt.Errorf("voiceclient: remote IP is required")
	}
	networkProto := networkProtocolForIP(remoteIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported TCP remote IP %s", remoteIP.String())
	}

	localAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	remoteAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(remoteIP),
		Port: uint16(remotePort),
	}
	conn, err := gonet.DialTCPWithBind(ctx, n.stack, localAddr, remoteAddr, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace TCP dial %s:%d: %w", remoteIP.String(), remotePort, err)
	}
	logger.Info("IMS SWu TCP connected",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort),
		logger.String("remote_ip", remoteIP.String()),
		logger.Int("remote_port", remotePort))
	return conn, nil
}

func (n *swuNetstack) DialContextUDP(ctx context.Context, localIP net.IP, localPort int, remoteIP net.IP, remotePort int) (net.Conn, error) {
	if remoteIP == nil {
		return nil, fmt.Errorf("voiceclient: remote IP is required")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	networkProto := networkProtocolForIP(remoteIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported UDP remote IP %s", remoteIP.String())
	}
	localAddr := &tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	remoteAddr := &tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(remoteIP),
		Port: uint16(remotePort),
	}
	conn, err := gonet.DialUDP(n.stack, localAddr, remoteAddr, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace UDP dial %s:%d: %w", remoteIP.String(), remotePort, err)
	}
	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	default:
	}
	logger.Info("IMS SWu UDP connected",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort),
		logger.String("remote_ip", remoteIP.String()),
		logger.Int("remote_port", remotePort))
	return conn, nil
}

func (n *swuNetstack) ListenContextTCP(ctx context.Context, localIP net.IP, localPort int) (net.Listener, error) {
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: local IP is required")
	}
	networkProto := networkProtocolForIP(localIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported listen IP %s", localIP.String())
	}
	localAddr := tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	ln, err := gonet.ListenTCP(n.stack, localAddr, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace TCP listen %s:%d: %w", localIP.String(), localPort, err)
	}
	logger.Info("IMS SWu TCP listening",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort))
	return &swuTCPListener{inner: ln, ctx: ctx}, nil
}

func (n *swuNetstack) ListenContextUDP(ctx context.Context, localIP net.IP, localPort int) (net.PacketConn, error) {
	if localIP == nil {
		return nil, fmt.Errorf("voiceclient: local IP is required")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	networkProto := networkProtocolForIP(localIP)
	if networkProto == 0 {
		return nil, fmt.Errorf("voiceclient: unsupported UDP listen IP %s", localIP.String())
	}
	localAddr := &tcpip.FullAddress{
		NIC:  swuNetstackNICID,
		Addr: addrFromNetIP(localIP),
		Port: uint16(localPort),
	}
	conn, err := gonet.DialUDP(n.stack, localAddr, nil, networkProto)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: SWu userspace UDP listen %s:%d: %w", localIP.String(), localPort, err)
	}
	logger.Info("IMS SWu UDP listening",
		logger.String("local_ip", localIP.String()),
		logger.Int("local_port", localPort))
	return conn, nil
}

type swuTCPListener struct {
	inner *gonet.TCPListener
	ctx   context.Context
}

func (l *swuTCPListener) Accept() (net.Conn, error) {
	if l.ctx != nil {
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
		}
	}
	return l.inner.Accept()
}

func (l *swuTCPListener) Close() error {
	return l.inner.Close()
}

func (l *swuTCPListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (n *swuNetstack) addLocalAddress() error {
	addr := addrFromNetIP(n.localIP)
	if addr.Len() == 0 {
		return fmt.Errorf("voiceclient: invalid SWu local IP %v", n.localIP)
	}
	protocol := networkProtocolForIP(n.localIP)
	if protocol == 0 {
		return fmt.Errorf("voiceclient: unsupported SWu local IP %s", n.localIP.String())
	}
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: prefixLenForIP(n.localIP),
		},
	}
	if err := n.stack.AddProtocolAddress(swuNetstackNICID, protocolAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("voiceclient: add SWu local IP %s to userspace netstack: %v", n.localIP.String(), err)
	}
	return nil
}

func (n *swuNetstack) inboundLoop() {
	for {
		select {
		case <-n.closed:
			return
		case packet, ok := <-n.dp.InnerPackets():
			if !ok {
				return
			}
			if len(packet) == 0 {
				continue
			}
			if n.dispatchRawIPPacket(packet) {
				continue
			}
			proto := networkProtocolForPacket(packet)
			if proto == 0 {
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), packet...)),
			})
			n.linkEP.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}
}

func (n *swuNetstack) outboundLoop() {
	for {
		select {
		case <-n.closed:
			return
		default:
		}
		pkt := n.linkEP.ReadContext(context.Background())
		if pkt == nil {
			select {
			case <-n.closed:
				return
			default:
				continue
			}
		}
		payload := packetBufferToBytes(pkt)
		pkt.DecRef()
		if len(payload) == 0 {
			continue
		}
		if err := n.dp.SendInnerPacket(payload); err != nil {
			logger.Warn("SWu outbound inner packet rejected",
				logger.String("error", err.Error()),
				logger.Int("packet_len", len(payload)))
		}
	}
}

func packetBufferToBytes(pkt *stack.PacketBuffer) []byte {
	if pkt == nil {
		return nil
	}
	sz := pkt.Size()
	if sz == 0 {
		return nil
	}
	buf := make([]byte, sz)
	v := pkt.ToBuffer()
	defer v.Release()
	flat := v.Flatten()
	if len(flat) == 0 {
		return nil
	}
	copy(buf, flat)
	return buf[:len(flat)]
}

func networkProtocolForPacket(packet []byte) tcpip.NetworkProtocolNumber {
	if len(packet) == 0 {
		return 0
	}
	switch packet[0] >> 4 {
	case 4:
		return ipv4.ProtocolNumber
	case 6:
		return ipv6.ProtocolNumber
	default:
		return 0
	}
}

func networkProtocolForIP(ip net.IP) tcpip.NetworkProtocolNumber {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return ipv4.ProtocolNumber
	}
	if ip.To16() != nil {
		return ipv6.ProtocolNumber
	}
	return 0
}

func addrFromNetIP(ip net.IP) tcpip.Address {
	if ip == nil {
		return tcpip.Address{}
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.AddrFromSlice(v4)
	}
	if v6 := ip.To16(); v6 != nil {
		return tcpip.AddrFromSlice(v6)
	}
	return tcpip.Address{}
}

func prefixLenForIP(ip net.IP) int {
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 32
	}
	return 128
}
