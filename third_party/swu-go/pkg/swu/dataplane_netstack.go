package swu

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/1239t/swu-go/pkg/ipsec"
	"github.com/1239t/swu-go/pkg/logger"
)

const netstackInnerQueueDepth = 256

func (s *Session) initNetstackDataplane() {
	if s.innerTx != nil {
		return
	}
	s.innerTx = make(chan []byte, netstackInnerQueueDepth)
	s.innerRx = make(chan []byte, netstackInnerQueueDepth)
	s.innerClosed = make(chan struct{})
}

func (s *Session) closeNetstackDataplane() {
	if s.innerClosed == nil {
		return
	}
	select {
	case <-s.innerClosed:
	default:
		close(s.innerClosed)
	}
	if s.innerRx != nil {
		close(s.innerRx)
	}
}

// SendInnerPacket injects an inner IPv4/IPv6 packet into the userspace ESP dataplane.
func (s *Session) SendInnerPacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	if s.innerTx == nil {
		return errors.New("netstack dataplane not initialized")
	}
	cp := append([]byte(nil), packet...)
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case <-s.innerClosed:
		return errors.New("netstack dataplane closed")
	case s.innerTx <- cp:
		return nil
	}
}

// InnerPackets returns the channel of inbound inner IP packets decrypted from ESP.
func (s *Session) InnerPackets() <-chan []byte {
	if s.innerRx == nil {
		ch := make(chan []byte)
		close(ch)
		return ch
	}
	return s.innerRx
}

func (s *Session) observeInnerPacket(packet []byte) {
	if s == nil || len(packet) == 0 {
		return
	}
	switch packet[0] >> 4 {
	case 4:
		s.innerIPv4Count.Add(1)
		if len(packet) < 20 {
			return
		}
		s.observeInnerProtocol(packet[9], packet[20:])
	case 6:
		s.innerIPv6Count.Add(1)
		if len(packet) < 40 {
			return
		}
		s.observeInnerProtocol(packet[6], packet[40:])
	}
}

func (s *Session) observeInnerProtocol(protocol uint8, payload []byte) {
	switch protocol {
	case 6:
		s.innerTCPCount.Add(1)
	case 17:
		s.innerUDPCount.Add(1)
	case 50:
		s.innerESPCount.Add(1)
	case 1:
		s.innerICMPv4Count.Add(1)
	case 58:
		s.innerICMPv6Count.Add(1)
		s.observeICMPv6(payload)
	}
}

func (s *Session) observeICMPv6(payload []byte) {
	if len(payload) < 1 {
		return
	}
	switch payload[0] {
	case 1:
		s.icmpv6DestUnreachableCount.Add(1)
	case 2:
		s.icmpv6PacketTooBigCount.Add(1)
		if len(payload) >= 8 {
			mtu := uint64(binary.BigEndian.Uint32(payload[4:8]))
			if mtu > 0 && mtu <= 1<<20 {
				s.icmpv6ReportedMTU.Store(mtu)
			}
		}
	case 3:
		s.icmpv6TimeExceededCount.Add(1)
	case 4:
		s.icmpv6ParameterProblemCount.Add(1)
	case 128:
		s.icmpv6EchoRequestCount.Add(1)
	case 129:
		s.icmpv6EchoReplyCount.Add(1)
	case 133:
		s.icmpv6RouterSolicitCount.Add(1)
	case 134:
		s.icmpv6RouterAdvertCount.Add(1)
	case 135:
		s.icmpv6NeighborSolicitCount.Add(1)
	case 136:
		s.icmpv6NeighborAdvertCount.Add(1)
	case 137:
		s.icmpv6RedirectCount.Add(1)
	default:
		s.icmpv6OtherCount.Add(1)
	}
}

func (s *Session) startNetstackDataPlaneLoop() {
	s.Logger.Info("ESP netstack 数据平面循环启动")

	go func() {
		var txCount, espSendCount, saDropCount uint64
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-s.innerClosed:
				return
			case packet, ok := <-s.innerTx:
				if !ok {
					return
				}
				if len(packet) == 0 {
					continue
				}
				txCount++

				var dstIP string
				var proto uint8
				if len(packet) > 0 {
					ver := packet[0] >> 4
					if ver == 4 && len(packet) >= 20 {
						dstIP = net.IP(packet[16:20]).String()
						proto = packet[9]
					} else if ver == 6 && len(packet) >= 40 {
						dstIP = net.IP(packet[24:40]).String()
						proto = packet[6]
					}
				}

				saOut := s.selectOutgoingSA(packet)
				if saOut == nil {
					saDropCount++
					if saDropCount <= 5 || saDropCount%100 == 0 {
						s.Logger.Warn("netstack ESP 出站 SA 为空，丢弃数据包",
							logger.Uint64("dropCount", saDropCount),
							logger.String("dstIP", dstIP),
							logger.Int("proto", int(proto)),
							logger.Int("len", len(packet)))
					}
					continue
				}

				espPacket, err := ipsec.Encapsulate(packet, saOut)
				if err != nil {
					s.Logger.Warn("netstack ESP 封装错误", logger.Err(err), logger.String("dstIP", dstIP))
					continue
				}
				if err := s.socket.SendESP(espPacket); err != nil {
					s.Logger.Warn("netstack ESP 发送失败", logger.Err(err), logger.String("dstIP", dstIP))
					continue
				}
				espSendCount++
			}
		}
	}()

	go func() {
		var espRecvCount, rxCount uint64
		for espData := range s.socket.ESPPackets() {
			select {
			case <-s.ctx.Done():
				return
			case <-s.innerClosed:
				return
			default:
			}

			espRecvCount++
			s.espRxCount.Add(1)

			var spi uint32
			if len(espData) >= 4 {
				spi = binary.BigEndian.Uint32(espData[0:4])
			}

			sa := s.ChildSAIn
			if len(espData) >= 4 && s.ChildSAsIn != nil {
				if hit, ok := s.ChildSAsIn[spi]; ok {
					sa = hit
				}
			}
			if sa == nil {
				s.espInboundSACount.Add(1)
				s.Logger.Warn("netstack ESP 入站 SA 为空，丢弃数据包", logger.Uint32("spi", spi), logger.Int("len", len(espData)))
				continue
			}

			packet, err := ipsec.Decapsulate(espData, sa)
			if err != nil {
				s.espDecapsulateCount.Add(1)
				s.Logger.Warn("netstack ESP 解封装错误", logger.Err(err), logger.Uint32("spi", spi), logger.Int("len", len(espData)))
				continue
			}
			s.observeInnerPacket(packet)

			cp := append([]byte(nil), packet...)
			select {
			case <-s.ctx.Done():
				return
			case <-s.innerClosed:
				return
			case s.innerRx <- cp:
				rxCount++
				s.espInnerRxCount.Add(1)
			default:
				s.espInnerQueueDropCount.Add(1)
				s.Logger.Warn("netstack 入站队列已满，丢弃数据包", logger.Int("len", len(packet)))
			}
		}
	}()
}
