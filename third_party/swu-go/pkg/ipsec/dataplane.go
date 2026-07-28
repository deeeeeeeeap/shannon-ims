package ipsec

import (
	"context"
	"net"
	"sync"

	"github.com/1239t/swu-go/pkg/logger"
)

// DataPlane 数据平面管理
// 分离 IKE 控制平面和 ESP 数据平面
type DataPlane struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// ESP 处理
	espSocket  *ESPSocket
	tunDevice  net.Conn
	inboundSA  *SecurityAssociation
	outboundSA *SecurityAssociation

	// 统计
	stats DataPlaneStats
	mu    sync.RWMutex
}

// DataPlaneStats 数据平面统计
type DataPlaneStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	BytesSent       uint64
	BytesReceived   uint64
	EncryptErrors   uint64
	DecryptErrors   uint64
}

// NewDataPlane 创建数据平面
func NewDataPlane(ctx context.Context, tun net.Conn, espSocket *ESPSocket) *DataPlane {
	dpCtx, cancel := context.WithCancel(ctx)
	return &DataPlane{
		ctx:       dpCtx,
		cancel:    cancel,
		espSocket: espSocket,
		tunDevice: tun,
	}
}

// SetSecurityAssociations 设置安全关联
func (dp *DataPlane) SetSecurityAssociations(inbound, outbound *SecurityAssociation) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	dp.inboundSA = inbound
	dp.outboundSA = outbound
}

// Start 启动数据平面处理
func (dp *DataPlane) Start() {
	dp.wg.Add(2)
	go dp.encryptLoop()
	go dp.decryptLoop()
}

// Stop 停止数据平面
func (dp *DataPlane) Stop() {
	dp.cancel()
	dp.wg.Wait()
}

// encryptLoop 加密循环：TUN -> ESP -> Network
func (dp *DataPlane) encryptLoop() {
	defer dp.wg.Done()

	buf := make([]byte, 2000) // MTU + overhead

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		// 从 TUN 读取明文
		n, err := dp.tunDevice.Read(buf)
		if err != nil {
			if dp.ctx.Err() != nil {
				return
			}
			logger.Debug("TUN 读取错误", logger.Err(err))
			continue
		}

		dp.mu.RLock()
		sa := dp.outboundSA
		dp.mu.RUnlock()

		if sa == nil {
			continue
		}

		// ESP 封装
		espPacket, err := Encapsulate(buf[:n], sa)
		if err != nil {
			dp.mu.Lock()
			dp.stats.EncryptErrors++
			dp.mu.Unlock()
			logger.Debug("ESP 封装错误", logger.Err(err))
			continue
		}

		// 发送到网络
		if err := dp.espSocket.Send(espPacket); err != nil {
			logger.Debug("ESP 发送错误", logger.Err(err))
			continue
		}

		dp.mu.Lock()
		dp.stats.PacketsSent++
		dp.stats.BytesSent += uint64(len(espPacket))
		dp.mu.Unlock()
	}
}

// decryptLoop 解密循环：Network -> ESP -> TUN
func (dp *DataPlane) decryptLoop() {
	defer dp.wg.Done()

	for {
		select {
		case <-dp.ctx.Done():
			return
		default:
		}

		// 从网络接收 ESP 包
		espPacket, err := dp.espSocket.Receive()
		if err != nil {
			if dp.ctx.Err() != nil {
				return
			}
			logger.Debug("ESP 接收错误", logger.Err(err))
			continue
		}

		dp.mu.RLock()
		sa := dp.inboundSA
		dp.mu.RUnlock()

		if sa == nil {
			continue
		}

		// ESP 解封装
		plaintext, err := Decapsulate(espPacket, sa)
		if err != nil {
			dp.mu.Lock()
			dp.stats.DecryptErrors++
			dp.mu.Unlock()
			logger.Debug("ESP 解封装错误", logger.Err(err))
			continue
		}

		// 写入 TUN
		if _, err := dp.tunDevice.Write(plaintext); err != nil {
			logger.Debug("TUN 写入错误", logger.Err(err))
			continue
		}

		dp.mu.Lock()
		dp.stats.PacketsReceived++
		dp.stats.BytesReceived += uint64(len(plaintext))
		dp.mu.Unlock()
	}
}

// GetStats 获取统计信息
func (dp *DataPlane) GetStats() DataPlaneStats {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	return dp.stats
}
