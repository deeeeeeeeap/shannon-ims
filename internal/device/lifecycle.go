package device

import (
	"fmt"
	"sync"
	"time"
)

// LifecyclePhase 表示设备生命周期的各个阶段
type LifecyclePhase string

const (
	// LifecyclePhaseOffline 设备处于离线状态
	LifecyclePhaseOffline LifecyclePhase = "offline"
	// LifecyclePhaseRebooting 设备正在重启中
	LifecyclePhaseRebooting LifecyclePhase = "rebooting"
	// LifecyclePhaseUSBWait 等待 USB 设备检测与加载
	LifecyclePhaseUSBWait LifecyclePhase = "usb_wait"
	// LifecyclePhaseWorkerStarting 工作线程启动中
	LifecyclePhaseWorkerStarting LifecyclePhase = "worker_starting"
	// LifecyclePhaseQMIStarting QMI 协议层初始化与启动中
	LifecyclePhaseQMIStarting LifecyclePhase = "qmi_starting"
	// LifecyclePhaseRecovering 设备处于故障恢复与健康重建阶段
	LifecyclePhaseRecovering LifecyclePhase = "recovering"
	// LifecyclePhaseOnline 设备正常在线且服务可用
	LifecyclePhaseOnline LifecyclePhase = "online"
	// LifecyclePhaseDegraded 设备处于降级运行状态
	LifecyclePhaseDegraded LifecyclePhase = "degraded"
	// LifecyclePhaseEvicting 设备正在被驱逐或移除
	LifecyclePhaseEvicting LifecyclePhase = "evicting"
)

// qmiLifecycleRecoveryTTL 定义了 QMI 生命周期恢复的默认生存时间（3 分钟）
const qmiLifecycleRecoveryTTL = 3 * time.Minute

// LifecycleSnapshot 记录设备生命周期的历史或当前快照信息
type LifecycleSnapshot struct {
	Phase         LifecyclePhase // 当前生命周期阶段
	Reason        string         // 切换到该阶段的原因/触发事件
	StartedAt     time.Time      // 阶段开始的时间戳
	Deadline      time.Time      // 故障恢复或预期切换的截止截止时间
	Recovering    bool           // 标识设备当前是否处于故障恢复流程中
	CanEvictAfter time.Time      // 允许对该设备执行驱逐操作的起始时间戳
}

// lifecycleCoordinator 用于线程安全地管理与协调池中所有设备的生命周期状态切换
type lifecycleCoordinator struct {
	mu     sync.RWMutex
	states map[string]LifecycleSnapshot
}

// newLifecycleCoordinator 创建并初始化一个新的生命周期协调器
func newLifecycleCoordinator() *lifecycleCoordinator {
	return &lifecycleCoordinator{states: make(map[string]LifecycleSnapshot)}
}

// lifecyclePhaseRecovering 判断给定的生命周期阶段是否属于某种“恢复中”状态
func lifecyclePhaseRecovering(phase LifecyclePhase) bool {
	switch phase {
	case LifecyclePhaseRebooting,
		LifecyclePhaseUSBWait,
		LifecyclePhaseWorkerStarting,
		LifecyclePhaseQMIStarting,
		LifecyclePhaseRecovering:
		return true
	default:
		return false
	}
}

// SetPhase 安全地将指定设备的生命周期阶段设置为目标状态，并指定原因与生存期时长
func (lc *lifecycleCoordinator) SetPhase(deviceID string, phase LifecyclePhase, reason string, ttl time.Duration) {
	lc.setPhaseAt(deviceID, phase, reason, time.Now(), ttl)
}

// setPhaseAt 执行具体的生命周期阶段设置逻辑，允许传入指定的时间戳（方便测试或校准）
func (lc *lifecycleCoordinator) setPhaseAt(deviceID string, phase LifecyclePhase, reason string, now time.Time, ttl time.Duration) {
	if lc == nil || deviceID == "" {
		return
	}
	snap := LifecycleSnapshot{
		Phase:      phase,
		Reason:     reason,
		StartedAt:  now,
		Recovering: lifecyclePhaseRecovering(phase),
	}
	if ttl > 0 {
		snap.Deadline = now.Add(ttl)
		snap.CanEvictAfter = snap.Deadline
	}
	lc.mu.Lock()
	lc.states[deviceID] = snap
	lc.mu.Unlock()
}

// BeginRecovery 启动设备的故障恢复流程，并设置默认或指定的恢复生存期 TTL
func (lc *lifecycleCoordinator) BeginRecovery(deviceID string, phase LifecyclePhase, reason string, ttl time.Duration) {
	lc.BeginRecoveryAt(deviceID, phase, reason, time.Now(), ttl)
}

// BeginRecoveryAt 在特定时间戳启动设备的故障恢复流程
func (lc *lifecycleCoordinator) BeginRecoveryAt(deviceID string, phase LifecyclePhase, reason string, now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		ttl = qmiLifecycleRecoveryTTL
	}
	lc.setPhaseAt(deviceID, phase, reason, now, ttl)
}

// FinishOnline 标志着设备已成功走完恢复/初始化流程，正式进入在线状态
func (lc *lifecycleCoordinator) FinishOnline(deviceID string) {
	lc.setPhaseAt(deviceID, LifecyclePhaseOnline, "control_online", time.Now(), 0)
}

// MarkOffline 将设备标记为离线状态，并记录具体的离线原因
func (lc *lifecycleCoordinator) MarkOffline(deviceID string, reason string) {
	lc.setPhaseAt(deviceID, LifecyclePhaseOffline, reason, time.Now(), 0)
}

// GetSnapshot 安全地获取指定设备当前的生命周期快照；若设备不存在，则返回离线状态快照
func (lc *lifecycleCoordinator) GetSnapshot(deviceID string) LifecycleSnapshot {
	if lc == nil || deviceID == "" {
		return LifecycleSnapshot{Phase: LifecyclePhaseOffline}
	}
	lc.mu.RLock()
	snap, ok := lc.states[deviceID]
	lc.mu.RUnlock()
	if !ok || snap.Phase == "" {
		return LifecycleSnapshot{Phase: LifecyclePhaseOffline}
	}
	return snap
}

// CanEvict 检查指定设备是否可以执行驱逐，如果处于恢复中且未超时则返回不可驱逐，并附带状态说明
func (lc *lifecycleCoordinator) CanEvict(deviceID string, now time.Time) (bool, string) {
	snap := lc.GetSnapshot(deviceID)
	if !snap.Recovering {
		return true, ""
	}
	if now.IsZero() {
		now = time.Now()
	}
	if snap.Deadline.IsZero() || now.Before(snap.Deadline) {
		return false, fmt.Sprintf("lifecycle_%s(%s)", snap.Phase, snap.Reason)
	}
	return true, fmt.Sprintf("lifecycle_deadline_expired(%s)", snap.Phase)
}
