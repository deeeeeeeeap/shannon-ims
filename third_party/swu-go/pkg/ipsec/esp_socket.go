package ipsec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// ESPSocket ESP 原始套接字
// 使用 IP 协议 50 (ESP) 直接收发 ESP 包
type ESPSocket struct {
	conn       *net.IPConn
	localAddr  net.IP
	remoteAddr net.IP
	rawFd      int
	timeout    time.Duration
}

// NewESPSocket 创建 ESP 原始套接字
func NewESPSocket(localIP, remoteIP string) (*ESPSocket, error) {
	local := net.ParseIP(localIP)
	remote := net.ParseIP(remoteIP)
	if local == nil || remote == nil {
		return nil, errors.New("无效的 IP 地址")
	}

	// 创建原始套接字
	// 协议号 50 = ESP
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 50)
	if err != nil {
		return nil, fmt.Errorf("创建原始套接字失败: %v", err)
	}

	// 设置 IP_HDRINCL (我们不包含 IP 头部)
	// 对于接收，内核会剥离 IP 头部
	// 对于发送，内核会添加 IP 头部

	// 绑定到本地地址
	addr := syscall.SockaddrInet4{
		Port: 0,
	}
	copy(addr.Addr[:], local.To4())
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("绑定失败: %v", err)
	}

	// 连接到远端 (可选，用于简化发送)
	remoteAddr := syscall.SockaddrInet4{}
	copy(remoteAddr.Addr[:], remote.To4())
	if err := syscall.Connect(fd, &remoteAddr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("连接失败: %v", err)
	}

	return &ESPSocket{
		localAddr:  local,
		remoteAddr: remote,
		rawFd:      fd,
		timeout:    5 * time.Second,
	}, nil
}

// Send 发送 ESP 包
func (s *ESPSocket) Send(data []byte) error {
	_, err := syscall.Write(s.rawFd, data)
	return err
}

// Receive 接收 ESP 包
func (s *ESPSocket) Receive() ([]byte, error) {
	buf := make([]byte, 2048)

	// 设置读取超时
	tv := durationToTimeval(
		int64(s.timeout/time.Second),
		int64((s.timeout%time.Second)/time.Microsecond),
	)
	syscall.SetsockoptTimeval(s.rawFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	n, err := syscall.Read(s.rawFd, buf)
	if err != nil {
		return nil, err
	}

	if n < 8 {
		return nil, errors.New("ESP 包太短")
	}

	return buf[:n], nil
}

// ReceiveFrom 接收 ESP 包并返回源地址
func (s *ESPSocket) ReceiveFrom() ([]byte, net.IP, error) {
	buf := make([]byte, 2048)

	n, from, err := syscall.Recvfrom(s.rawFd, buf, 0)
	if err != nil {
		return nil, nil, err
	}

	if n < 8 {
		return nil, nil, errors.New("ESP 包太短")
	}

	// 解析源地址
	var srcIP net.IP
	if addr, ok := from.(*syscall.SockaddrInet4); ok {
		srcIP = net.IP(addr.Addr[:])
	}

	return buf[:n], srcIP, nil
}

// SetTimeout 设置超时
func (s *ESPSocket) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

// Close 关闭套接字
func (s *ESPSocket) Close() error {
	return syscall.Close(s.rawFd)
}

// GetSPI 从 ESP 包中提取 SPI
func GetSPI(espPacket []byte) (uint32, error) {
	if len(espPacket) < 4 {
		return 0, errors.New("ESP 包太短")
	}
	return binary.BigEndian.Uint32(espPacket[0:4]), nil
}

// GetSequenceNumber 从 ESP 包中提取序列号
func GetSequenceNumber(espPacket []byte) (uint32, error) {
	if len(espPacket) < 8 {
		return 0, errors.New("ESP 包太短")
	}
	return binary.BigEndian.Uint32(espPacket[4:8]), nil
}

// NewESPSocketUDP 创建基于 UDP 的 ESP 套接字 (NAT-T)
// 用于 UDP 封装的 ESP (端口 4500)
type ESPSocketUDP struct {
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
}

// NewESPSocketUDP 创建 UDP 封装的 ESP 套接字
func NewESPSocketUDP(localAddr, remoteAddr string) (*ESPSocketUDP, error) {
	local, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}

	remote, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, err
	}

	return &ESPSocketUDP{
		conn:       conn,
		remoteAddr: remote,
	}, nil
}

// Send 发送 UDP 封装的 ESP 包
// NAT-T: 在 ESP 包前添加 4 字节的 Non-ESP Marker (全零表示 ESP)
func (s *ESPSocketUDP) Send(data []byte) error {
	// 对于 NAT-T ESP，不需要额外标记
	// SPI != 0 表示这是 ESP 包
	_, err := s.conn.WriteToUDP(data, s.remoteAddr)
	return err
}

// Receive 接收 UDP 封装的 ESP 包
func (s *ESPSocketUDP) Receive() ([]byte, error) {
	buf := make([]byte, 2048)
	n, _, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	// 检查是否是 IKE 包 (SPI 可能是 0)
	// 或者是 NAT-keepalive (1 字节 0xff)
	if n == 1 && buf[0] == 0xff {
		return nil, errors.New("NAT-keepalive 包")
	}

	return buf[:n], nil
}

// Close 关闭套接字
func (s *ESPSocketUDP) Close() error {
	return s.conn.Close()
}
