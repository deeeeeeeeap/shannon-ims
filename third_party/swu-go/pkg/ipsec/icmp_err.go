package ipsec

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/1239t/swu-go/pkg/logger"
	"golang.org/x/sys/unix"
)

// NetEvent 描述从错误队列收到的网络事件
type NetEvent struct {
	Type    NetEventType
	PMTU    uint32 // 如果是 PathMTU，这里会有新的 MTU
	Reason  string
	OldPort int // NAT-T 端口漂移前的旧端口
	NewPort int // NAT-T 端口漂移后的新端口
}

type NetEventType int

const (
	EventPathMTU        NetEventType = iota // 收到了 ICMP Frag Needed / Packet Too Big
	EventNetworkDown                        // 收到了 Host / Net Unreachable (用于 DPD 欺骗预测)
	EventNATPortChanged                     // NAT-T 端口漂移：远端源端口发生了变化 (RFC 3947)
)

// ParseSockExtError 解析 OOB 数据里的 sock_extended_err
func ParseSockExtError(oob []byte) (*unix.SockExtendedErr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		if (m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR) ||
			(m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR) {
			if len(m.Data) >= int(unsafe.Sizeof(unix.SockExtendedErr{})) {
				see := (*unix.SockExtendedErr)(unsafe.Pointer(&m.Data[0]))
				return see, nil
			}
		}
	}
	return nil, fmt.Errorf("no sock_extended_err found")
}

// startErrorListener 启动针对当前 socket fd 的 MSG_ERRQUEUE 监听
func (s *SocketManager) startErrorListener() {
	if s.NetEvents == nil {
		s.NetEvents = make(chan NetEvent, 10)
	}

	rawConn, err := s.Conn.SyscallConn()
	if err != nil {
		logger.Warn("Failed to get SyscallConn for ErrorQueue", logger.Err(err))
		return
	}

	// 开启 RECVERR 让内核把 ICMP 错误丢进 ErrorQueue
	isIPv6 := s.LocalAddr != nil && s.LocalAddr.IP.To4() == nil
	err = rawConn.Control(func(fd uintptr) {
		if isIPv6 {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
		} else {
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVERR, 1)
		}
	})
	if err != nil {
		logger.Warn("Failed to set IP_RECVERR", logger.Err(err))
		return
	}

	go func() {
		for {
			select {
			case <-s.closeChan:
				return
			default:
			}

			// 挂起直到 socket 变为可读或者有 error queue event
			err := rawConn.Read(func(fd uintptr) bool {
				buf := make([]byte, 1024)
				oob := make([]byte, 1024)

				for {
					// PEEK & 非阻塞读取 ERRQUEUE
					_, oobn, _, _, recvErr := syscall.Recvmsg(int(fd), buf, oob, syscall.MSG_ERRQUEUE|syscall.MSG_DONTWAIT)
					if recvErr != nil {
						// 队列为空，退出闭包等待下一次可读事件
						return true
					}

					if oobn > 0 {
						see, _ := ParseSockExtError(oob[:oobn])
						if see != nil && (see.Origin == unix.SO_EE_ORIGIN_ICMP || see.Origin == unix.SO_EE_ORIGIN_ICMP6) {
							// 提取底层错误
							// EMSGSIZE (90) = Fragmentation Needed (需要调低 MTU)
							// EHOSTUNREACH (113), ENETUNREACH (101) = 链路可能断开
							if see.Errno == uint32(unix.EMSGSIZE) {
								if see.Info > 500 && see.Info < 1500 { // 过滤非法小包
									select {
									case s.NetEvents <- NetEvent{Type: EventPathMTU, PMTU: see.Info}:
									default:
									}
								}
							} else if see.Errno == uint32(unix.EHOSTUNREACH) || see.Errno == uint32(unix.ENETUNREACH) {
								select {
								case s.NetEvents <- NetEvent{Type: EventNetworkDown, Reason: fmt.Sprintf("ICMP dest unreachable: %d", see.Errno)}:
								default:
								}
							}
						}
					}
				}
			})
			if err != nil {
				// SyscallConn closed
				return
			}
		}
	}()
}
