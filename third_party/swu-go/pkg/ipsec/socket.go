package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

type SocketManager struct {
	Conn       *net.UDPConn
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	remoteIPs  []net.IP
	remoteMu   sync.Mutex
	remoteIdx  uint32

	IKEChan   chan []byte
	ESPChan   chan []byte
	NetEvents chan NetEvent // 网络底层事件通道 (PMTU / ICMP Error)

	closeChan chan struct{}
	wg        sync.WaitGroup

	receivedIKE uint64
	receivedESP uint64
	droppedIKE  uint64
	droppedESP  uint64
}

func (s *SocketManager) IKEPackets() <-chan []byte {
	return s.IKEChan
}

func (s *SocketManager) ESPPackets() <-chan []byte {
	return s.ESPChan
}

func (s *SocketManager) NetEventsChan() <-chan NetEvent {
	return s.NetEvents
}

func NewSocketManager(local, remote string, dnsServer string) (*SocketManager, error) {
	rAddr, remoteIPs, err := resolveUDPAddrAll(remote, dnsServer)
	if err != nil {
		return nil, err
	}
	if len(remoteIPs) == 0 && rAddr.IP != nil {
		remoteIPs = []net.IP{rAddr.IP}
	}

	network := "udp6"
	if rAddr.IP != nil && rAddr.IP.To4() != nil {
		network = "udp4"
	}

	lAddr, err := net.ResolveUDPAddr(network, local)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP(network, lAddr)
	if err != nil {
		return nil, err
	}

	if actual, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		lAddr = actual
	}

	return &SocketManager{
		Conn:       conn,
		LocalAddr:  lAddr,
		RemoteAddr: rAddr,
		remoteIPs:  remoteIPs,
		IKEChan:    make(chan []byte, 100),
		ESPChan:    make(chan []byte, 1000), // 数据平面的更高缓冲区
		NetEvents:  make(chan NetEvent, 10),
		closeChan:  make(chan struct{}),
	}, nil
}

func resolveUDPAddrAll(addr string, dnsServer string) (*net.UDPAddr, []net.IP, error) {
	if dnsServer == "" {
		r, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, nil, err
		}
		if r.IP != nil {
			return r, []net.IP{r.IP}, nil
		}
		return r, nil, nil
	}

	if dnsServer == "" {
		r, err := net.ResolveUDPAddr("udp", addr)
		return r, nil, err
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return nil, nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, []net.IP{ip}, nil
	}

	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := res.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, errors.New("DNS 未返回 IP")
	}

	var remoteIPs []net.IP
	for _, cand := range ips {
		if cand.IP == nil {
			continue
		}
		remoteIPs = append(remoteIPs, cand.IP)
	}

	ip := remoteIPs[0]
	for _, cand := range ips {
		if cand.IP.To4() != nil {
			ip = cand.IP
			break
		}
	}

	return &net.UDPAddr{IP: ip, Port: port}, remoteIPs, nil
}

func (s *SocketManager) Start() {
	s.wg.Add(1)
	go s.readLoop()

	// 启动 ICMP MSG_ERRQUEUE 错误监听
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.startErrorListener()
	}()
}

func (s *SocketManager) Stop() {
	select {
	case <-s.closeChan:
	default:
		close(s.closeChan)
	}
	s.Conn.Close()
	s.wg.Wait()
	close(s.IKEChan)
	close(s.ESPChan)
	close(s.NetEvents)
}

func (s *SocketManager) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, 4096) // Max MTU usually 1500

	for {
		n, addr, err := s.Conn.ReadFromUDP(buf)
		if err != nil {
			// Log checking if closed
			return
		}

		s.remoteMu.Lock()
		allowed := len(s.remoteIPs) == 0
		for _, rip := range s.remoteIPs {
			if addr.IP.Equal(rip) {
				allowed = true
				if len(s.remoteIPs) > 1 {
					s.RemoteAddr.IP = addr.IP
					s.remoteIPs = []net.IP{addr.IP}
					s.remoteIdx = 0
					logger.Debug("锁定 ePDG 目标", logger.String("ip", addr.IP.String()))
				}
				break
			}
		}
		s.remoteMu.Unlock()
		if !allowed {
			continue
		}

		// NAT-T 端口漂移检测 (RFC 3947/3948)
		// 如果来源 IP 校验通过但端口发生变化，说明家庭路由器的 NAT 映射已被翻新
		s.remoteMu.Lock()
		if addr.Port != s.RemoteAddr.Port && addr.Port > 0 {
			oldPort := s.RemoteAddr.Port
			s.RemoteAddr.Port = addr.Port
			s.remoteMu.Unlock()
			logger.Info("NAT-T 端口漂移检测：远端源端口发生变化，已动态跟随",
				logger.Int("old_port", oldPort),
				logger.Int("new_port", addr.Port),
				logger.String("remote_ip", addr.IP.String()))
			// 通知上层会话（非阻塞）
			select {
			case s.NetEvents <- NetEvent{
				Type:    EventNATPortChanged,
				OldPort: oldPort,
				NewPort: addr.Port,
				Reason:  fmt.Sprintf("NAT port changed %d -> %d", oldPort, addr.Port),
			}:
			default:
			}
		} else {
			s.remoteMu.Unlock()
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		if n == 1 && data[0] == 0xff {
			continue
		}

		if ikeData, ok := parseIKEPayload(data); ok {
			select {
			case s.IKEChan <- ikeData:
				atomic.AddUint64(&s.receivedIKE, 1)
			default:
				drops := atomic.AddUint64(&s.droppedIKE, 1)
				if drops == 1 || drops%100 == 0 {
					logger.Warn("IKE Channel 已满，丢弃数据包", logger.Uint64("dropped", drops))
				}
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
		case s.ESPChan <- data:
			atomic.AddUint64(&s.receivedESP, 1)
		default:
			drops := atomic.AddUint64(&s.droppedESP, 1)
			if drops == 1 || drops%100 == 0 {
				logger.Warn("ESP Channel 已满，丢弃数据包", logger.Uint64("dropped", drops))
			}
		}
	}
}

func (s *SocketManager) SendIKE(data []byte) error {
	s.remoteMu.Lock()
	if len(s.remoteIPs) > 1 {
		idx := int(s.remoteIdx % uint32(len(s.remoteIPs)))
		s.remoteIdx++
		s.RemoteAddr.IP = s.remoteIPs[idx]
		logger.Debug("切换 ePDG 目标", logger.String("ip", s.RemoteAddr.IP.String()))
	}
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()

	packet := data
	if dst.Port == 4500 {
		packet = append([]byte{0, 0, 0, 0}, data...)
	}
	_, err := s.Conn.WriteToUDP(packet, &dst)
	return err
}

func (s *SocketManager) SendESP(data []byte) error {
	s.remoteMu.Lock()
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()
	packet := data
	// ESP over UDP 不添加 Non-ESP Marker (RFC 3948)
	// 接收方通过 SPI != 0 来区分 ESP 和 IKE
	n, err := s.Conn.WriteToUDP(packet, &dst)
	if err != nil {
		logger.Warn("ESP 发送失败", logger.Err(err), logger.String("dst", dst.String()), logger.Int("len", len(packet)))
	} else if n != len(packet) {
		logger.Warn("ESP 发送不完整", logger.Int("sent", n), logger.Int("expected", len(packet)))
	}
	return err
}

func (s *SocketManager) SendNATKeepalive() error {
	s.remoteMu.Lock()
	dst := *s.RemoteAddr
	s.remoteMu.Unlock()
	_, err := s.Conn.WriteToUDP([]byte{0xff}, &dst)
	if err != nil {
		// 捕捉 operation not permitted 这类 OS 级阻塞
		logger.Warn("NAT keepalive 发送遭遇操作系统级拦截/拒绝", logger.Err(err), logger.String("dst", dst.String()), logger.String("local", s.LocalAddrString()))
	}
	return err
}

// ReceiveIKE 从 IKE 通道接收数据 (阻塞)
func (s *SocketManager) ReceiveIKE() ([]byte, error) {
	data, ok := <-s.IKEChan
	if !ok {
		return nil, fmt.Errorf("IKE 通道已关闭")
	}
	return data, nil
}

func (s *SocketManager) SetRemotePort(port int) {
	s.RemoteAddr.Port = port
}

func (s *SocketManager) LocalPort() uint16 {
	if s.LocalAddr == nil {
		return 0
	}
	return uint16(s.LocalAddr.Port)
}

func (s *SocketManager) LocalIP() net.IP {
	if s.LocalAddr == nil {
		return nil
	}
	return s.LocalAddr.IP
}

func (s *SocketManager) RemoteIP() net.IP {
	if s.RemoteAddr == nil {
		return nil
	}
	return s.RemoteAddr.IP
}

func (s *SocketManager) RemotePort() int {
	if s.RemoteAddr == nil {
		return 0
	}
	return s.RemoteAddr.Port
}

func (s *SocketManager) LocalAddrString() string {
	if s.LocalAddr == nil {
		return ""
	}
	return s.LocalAddr.String()
}

func (s *SocketManager) RemoteAddrString() string {
	if s.RemoteAddr == nil {
		return ""
	}
	return s.RemoteAddr.String()
}

func parseIKEPayload(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if binary.BigEndian.Uint32(data[:4]) == 0 {
		if len(data) < 4+ikev2.IKE_HEADER_LEN {
			return nil, false
		}
		ikeData := data[4:]
		if looksLikeIKE(ikeData) {
			return ikeData, true
		}
		return nil, false
	}

	if len(data) < ikev2.IKE_HEADER_LEN {
		return nil, false
	}
	if looksLikeIKE(data) {
		return data, true
	}
	return nil, false
}

func looksLikeIKE(data []byte) bool {
	if len(data) < ikev2.IKE_HEADER_LEN {
		return false
	}
	if data[17] != 0x20 {
		return false
	}
	ex := ikev2.ExchangeType(data[18])
	switch ex {
	case ikev2.IKE_SA_INIT, ikev2.IKE_AUTH, ikev2.CREATE_CHILD_SA, ikev2.INFORMATIONAL:
		return true
	default:
		return false
	}
}

type SocketStats struct {
	ReceivedIKE uint64
	ReceivedESP uint64
	DroppedIKE  uint64
	DroppedESP  uint64
}

func (s *SocketManager) Stats() SocketStats {
	return SocketStats{
		ReceivedIKE: atomic.LoadUint64(&s.receivedIKE),
		ReceivedESP: atomic.LoadUint64(&s.receivedESP),
		DroppedIKE:  atomic.LoadUint64(&s.droppedIKE),
		DroppedESP:  atomic.LoadUint64(&s.droppedESP),
	}
}

// RawFD 返回底层 UDP socket 的文件描述符
// 用于 XFRM SA 的 ESP-in-UDP encap 配置
func (s *SocketManager) RawFD() (int, error) {
	rawConn, err := s.Conn.SyscallConn()
	if err != nil {
		return -1, fmt.Errorf("获取 SyscallConn 失败: %v", err)
	}

	var fd int
	var fdErr error
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, fmt.Errorf("获取 FD 失败: %v", err)
	}
	return fd, fdErr
}

// SetUDPEncap 在 socket 上设置 UDP_ENCAP_ESPINUDP
// 使内核 XFRM 通过此 socket 收发 ESP-in-UDP 包
// 设置后，内核会自动处理 ESP 包的 UDP 封装/解封装
func (s *SocketManager) SetUDPEncap() error {
	rawConn, err := s.Conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("获取 SyscallConn 失败: %v", err)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		// UDP_ENCAP = 100, UDP_ENCAP_ESPINUDP = 2
		const (
			solUDP           = 17 // SOL_UDP
			udpEncap         = 100
			udpEncapESPInUDP = 2
		)
		setErr = syscall.SetsockoptInt(int(fd), solUDP, udpEncap, udpEncapESPInUDP)
	})
	if err != nil {
		return fmt.Errorf("Control 调用失败: %v", err)
	}
	if setErr != nil {
		return fmt.Errorf("设置 UDP_ENCAP_ESPINUDP 失败: %v", setErr)
	}

	logger.Info("已在 socket 上设置 UDP_ENCAP_ESPINUDP",
		logger.String("local", s.LocalAddr.String()))
	return nil
}
