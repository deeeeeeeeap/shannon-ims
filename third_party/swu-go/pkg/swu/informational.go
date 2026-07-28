package swu

import (
	"encoding/binary"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// sendDPD 发送 Dead Peer Detection 请求，返回的 err 仅指打包入列错误
func (s *Session) sendDPD() error {
	s.Logger.Debug("发送 DPD 请求 (通过并发窗口队列)")
	// 滑动窗口已经接管了超时重试惩罚，这句 send 函数其实就是投信箱拿号过程。
	_, err := s.sendEncryptedWithRetry(nil, ikev2.INFORMATIONAL)
	return err
}

// DPDProbe 提供给上层（如 SIP）主动发起 DPD 探测的接口。
// 它强制触发一个 DPD 报文并由底层滑动窗口负责重传，如果底层在重传耗尽后仍无响应，
// 底层会自动触发 OnSessionDown 并终止 Session，同时这里的返回 err 也仅表示投递失败。
func (s *Session) DPDProbe() error {
	return s.sendDPD()
}

// sendDeleteIKE 发送 IKE SA 删除通知
func (s *Session) sendDeleteIKE() error {
	s.Logger.Debug("发送 IKE SA Delete 通知")
	del := &ikev2.EncryptedPayloadDelete{
		ProtocolID: ikev2.ProtoIKE,
		SPISize:    0,
		NumSPIs:    0,
		SPIs:       nil,
	}
	pkt, err := s.encryptAndWrap([]ikev2.Payload{del}, ikev2.INFORMATIONAL, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(pkt)
}

// sendDeleteChildSA 发送 Child SA 删除通知
func (s *Session) sendDeleteChildSA(spis []uint32) error {
	s.Logger.Debug("发送 Child SA Delete 通知", logger.Int("count", len(spis)))
	if len(spis) == 0 {
		return nil
	}
	raw := make([]byte, 0, 4*len(spis))
	for _, spi := range spis {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, spi)
		raw = append(raw, b...)
	}
	del := &ikev2.EncryptedPayloadDelete{
		ProtocolID: ikev2.ProtoESP,
		SPISize:    4,
		NumSPIs:    uint16(len(spis)),
		SPIs:       raw,
	}
	pkt, err := s.encryptAndWrap([]ikev2.Payload{del}, ikev2.INFORMATIONAL, false)
	if err != nil {
		return err
	}
	return s.socket.SendIKE(pkt)
}

// StartDPD 启动 DPD 后台任务（对齐 strongSwan ike_sa.c:send_dpd）
// strongSwan 策略：
//  1. 检查 lastInboundTime（入站时间差），有流量则跳过 DPD 请求
//  2. DPD 发送由 sendEncryptedWithRetry 负责超时重传（5次/~165s）
//  3. 重传耗尽 → 判定对端不可达，触发隧道重建
func (s *Session) StartDPD(interval time.Duration) {
	// 初始化入站时间戳
	if s.lastInboundTime.IsZero() {
		s.lastInboundTime = time.Now()
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				// strongSwan 策略：检查入站时间差，有流量则跳过 DPD
				diff := time.Since(s.lastInboundTime)
				if diff < interval {
					// 入站间隔内有流量，对端存活，无需 DPD
					continue
				}

				// 超过 DPD 间隔无入站流量，发送 DPD 探测
				s.Logger.Debug("发送 DPD 请求",
					logger.Duration("lastInbound", diff))
				if err := s.sendDPD(); err != nil {
					// sendDPD → sendEncryptedWithRetry 已经做了 5 次指数退避重传
					// 到达这里说明 ~165s 内全部超时，判定对端不可达
					s.Logger.Error("DPD 重传耗尽，判定对端不可达",
						logger.Err(err))

					// 暴力掐除：立即发送底层断线回调
					if s.OnSessionDown != nil {
						go s.OnSessionDown()
					}
					// 紧接着注销 Context 以打断本 Session 所有被挂起的任务和网络发包
					if s.cancel != nil {
						s.cancel()
					}
					return
				}
				// DPD 成功 → 更新入站时间戳
				s.lastInboundTime = time.Now()
			}
		}
	}()
}
