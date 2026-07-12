//go:build linux

package runtimehost

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	externalipsec "github.com/1239t/swu-go/pkg/ipsec"
	externalswu "github.com/1239t/swu-go/pkg/swu"
	"github.com/1239t/vowifi-go/runtimehost/ikev2"
	"github.com/1239t/vowifi-go/runtimehost/transport"
)

type swuDatagramTransport struct {
	tp         transport.DatagramTransport
	remoteAddr *net.UDPAddr
	ikeCh      chan []byte
	espCh      chan []byte
	netEvents  chan externalipsec.NetEvent
	closeOnce  sync.Once
	done       chan struct{}
}

func newSWuDatagramTransport(tp transport.DatagramTransport, remoteAddr *net.UDPAddr) *swuDatagramTransport {
	return &swuDatagramTransport{
		tp:         tp,
		remoteAddr: remoteAddr,
		ikeCh:      make(chan []byte, 100),
		espCh:      make(chan []byte, 1000),
		netEvents:  make(chan externalipsec.NetEvent, 10),
		done:       make(chan struct{}),
	}
}

func (t *swuDatagramTransport) Start() {
	go t.readLoop()
}

func (t *swuDatagramTransport) Stop() {
	t.closeOnce.Do(func() {
		_ = t.tp.Close()
		<-t.done
		close(t.ikeCh)
		close(t.espCh)
		close(t.netEvents)
	})
}

func (t *swuDatagramTransport) SendIKE(data []byte) error {
	if t.remoteAddr == nil {
		return fmt.Errorf("swu proxy transport: remote address unavailable")
	}
	packet := data
	if t.remoteAddr.Port == 4500 {
		packet = append([]byte{0, 0, 0, 0}, data...)
	}
	_, err := t.tp.SendTo(packet, t.remoteAddr)
	return err
}

func (t *swuDatagramTransport) SendESP(data []byte) error {
	if t.remoteAddr == nil {
		return fmt.Errorf("swu proxy transport: remote address unavailable")
	}
	_, err := t.tp.SendTo(data, t.remoteAddr)
	return err
}

func (t *swuDatagramTransport) IKEPackets() <-chan []byte {
	return t.ikeCh
}

func (t *swuDatagramTransport) ESPPackets() <-chan []byte {
	return t.espCh
}

func (t *swuDatagramTransport) NetEventsChan() <-chan externalipsec.NetEvent {
	return t.netEvents
}

func (t *swuDatagramTransport) LocalPort() uint16 {
	if ua, ok := t.tp.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		return uint16(ua.Port)
	}
	return 0
}

func (t *swuDatagramTransport) LocalIP() net.IP {
	if ua, ok := t.tp.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		return append(net.IP(nil), ua.IP...)
	}
	return nil
}

func (t *swuDatagramTransport) RemoteIP() net.IP {
	if t.remoteAddr == nil || t.remoteAddr.IP == nil {
		return nil
	}
	return append(net.IP(nil), t.remoteAddr.IP...)
}

func (t *swuDatagramTransport) RemotePort() int {
	if t.remoteAddr == nil {
		return 0
	}
	return t.remoteAddr.Port
}

func (t *swuDatagramTransport) SetRemotePort(port int) {
	if t.remoteAddr != nil && port > 0 {
		t.remoteAddr.Port = port
	}
}

func (t *swuDatagramTransport) LocalAddrString() string {
	if addr := t.tp.LocalAddr(); addr != nil {
		return addr.String()
	}
	return ""
}

func (t *swuDatagramTransport) RelayAddrString() string {
	if rp, ok := t.tp.(interface{ RelayAddr() *net.UDPAddr }); ok {
		if relay := rp.RelayAddr(); relay != nil {
			return relay.String()
		}
	}
	return ""
}

func (t *swuDatagramTransport) RemoteAddrString() string {
	if t.remoteAddr == nil {
		return ""
	}
	return t.remoteAddr.String()
}

func (t *swuDatagramTransport) readLoop() {
	defer close(t.done)
	buf := make([]byte, 65535)
	for {
		n, _, err := t.tp.RecvFrom(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		data := append([]byte(nil), buf[:n]...)
		if len(data) == 1 && data[0] == 0xff {
			continue
		}
		if ikeData, ok := parseSWuIKEPayload(data); ok {
			select {
			case t.ikeCh <- ikeData:
			default:
			}
			continue
		}
		if len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == 0 {
			data = data[4:]
		}
		if len(data) == 0 {
			continue
		}
		select {
		case t.espCh <- data:
		default:
		}
	}
}

func parseSWuIKEPayload(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if binary.BigEndian.Uint32(data[:4]) == 0 {
		if len(data) < 4+ikev2.IKE_HEADER_LEN {
			return nil, false
		}
		ikeData := data[4:]
		if looksLikeSWuIKE(ikeData) {
			return ikeData, true
		}
		return nil, false
	}
	if len(data) < ikev2.IKE_HEADER_LEN {
		return nil, false
	}
	if looksLikeSWuIKE(data) {
		return data, true
	}
	return nil, false
}

func looksLikeSWuIKE(data []byte) bool {
	if len(data) < ikev2.IKE_HEADER_LEN {
		return false
	}
	if data[17] != 0x20 {
		return false
	}
	switch ikev2.ExchangeType(data[18]) {
	case ikev2.IKE_SA_INIT, ikev2.IKE_AUTH, ikev2.CREATE_CHILD_SA, ikev2.INFORMATIONAL:
		return true
	default:
		return false
	}
}

func buildSWuTransportFactory(proxy *ProxyConfig) func(string, string) (externalswu.Transport, error) {
	routePolicy := buildRoutePolicy(proxy)
	if routePolicy.Kind != transport.ProxySocks5UDPAssociate {
		return nil
	}
	return func(local, remote string) (externalswu.Transport, error) {
		_ = strings.TrimSpace(local)
		remoteAddr, err := net.ResolveUDPAddr("udp", remote)
		if err != nil {
			return nil, fmt.Errorf("swu proxy transport resolve remote %q: %w", remote, err)
		}
		tp, err := transport.NewSocks5UDPTransport(routePolicy.Addr, routePolicy.Username, routePolicy.Password)
		if err != nil {
			return nil, err
		}
		return newSWuDatagramTransport(tp, remoteAddr), nil
	}
}
