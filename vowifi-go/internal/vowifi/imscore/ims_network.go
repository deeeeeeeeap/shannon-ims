package imscore

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// IMSNetwork abstracts userspace or system IMS dataplane sockets.
type IMSNetwork interface {
	DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error)
	HasLocalIP(ip []byte) bool
	ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error)
	ListenTCP(ctx context.Context, laddr *net.TCPAddr) (net.Listener, error)
	LocalIP() []byte
	ResolveIP(ctx context.Context, host string, preferIPv6 bool) ([]byte, error)
}

// UserspaceIMSNetwork routes IMS sockets through the SWu userspace netstack.
type UserspaceIMSNetwork struct {
	localIP net.IP
	swu     voiceclient.SWUTCPDialer
}

// NewUserspaceIMSNetwork builds an IMSNetwork backed by the established SWu dataplane.
func NewUserspaceIMSNetwork(localIP net.IP, dataplane voiceclient.PacketDataplane) (*UserspaceIMSNetwork, error) {
	if localIP == nil {
		return nil, fmt.Errorf("imscore: local IP is required")
	}
	swu, err := newSWUNetstack(localIP, dataplane)
	if err != nil {
		return nil, err
	}
	return &UserspaceIMSNetwork{localIP: localIP, swu: swu}, nil
}

func (n *UserspaceIMSNetwork) DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	localPort := 5060
	if l, ok := ctx.Value(localPortContextKey{}).(int); ok && l > 0 {
		localPort = l
	}
	mode := canonicalRegisterTransport(transport)
	if mode == "udp" || network == "udp" {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr == nil {
			return nil, fmt.Errorf("imscore: invalid UDP addr %v", addr)
		}
		return n.swu.DialContextUDP(ctx, n.localIP, localPort, udpAddr.IP, udpAddr.Port)
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid TCP addr %v", addr)
	}
	return n.swu.DialContextTCP(ctx, n.localIP, localPort, tcpAddr.IP, tcpAddr.Port)
}

func (n *UserspaceIMSNetwork) HasLocalIP(ip []byte) bool {
	if n == nil || n.localIP == nil || len(ip) == 0 {
		return false
	}
	return n.localIP.Equal(net.IP(ip))
}

func (n *UserspaceIMSNetwork) ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid UDP listen addr %v", addr)
	}
	port := udpAddr.Port
	if port <= 0 {
		port = 5060
	}
	return n.swu.ListenContextUDP(ctx, n.localIP, port)
}

func (n *UserspaceIMSNetwork) ListenTCP(ctx context.Context, laddr *net.TCPAddr) (net.Listener, error) {
	if n == nil || n.swu == nil {
		return nil, fmt.Errorf("imscore: userspace IMS network unavailable")
	}
	if laddr == nil {
		return nil, fmt.Errorf("imscore: listen addr is required")
	}
	port := laddr.Port
	if port <= 0 {
		port = 5060
	}
	return n.swu.ListenContextTCP(ctx, n.localIP, port)
}

func (n *UserspaceIMSNetwork) LocalIP() []byte {
	if n == nil || n.localIP == nil {
		return nil
	}
	return append([]byte(nil), n.localIP...)
}

func (n *UserspaceIMSNetwork) ResolveIP(ctx context.Context, host string, preferIPv6 bool) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("imscore: resolve %q: %w", host, err)
	}
	if preferIPv6 {
		for _, ip := range ips {
			if ip.To4() == nil {
				return ip, nil
			}
		}
	}
	return ips[0], nil
}

func (n *UserspaceIMSNetwork) SWUDialer() voiceclient.SWUTCPDialer {
	if n == nil {
		return nil
	}
	return n.swu
}

func (n *UserspaceIMSNetwork) Close() error {
	if n == nil || n.swu == nil {
		return nil
	}
	return n.swu.Close()
}

type localPortContextKey struct{}

func withLocalPort(ctx context.Context, port int) context.Context {
	if port <= 0 {
		return ctx
	}
	return context.WithValue(ctx, localPortContextKey{}, port)
}

func splitHostPortAddr(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid host %q", host)
	}
	return ip, port, nil
}
