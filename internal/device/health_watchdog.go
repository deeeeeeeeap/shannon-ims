package device

import (
	"strings"
	"time"
)

// HealthLayer 定义了监控健康状态的协议/组件分层
type HealthLayer string

const (
	// HealthLayerAT AT 协议控制层
	HealthLayerAT HealthLayer = "at"
	// HealthLayerQMI QMI 协议传输控制层
	HealthLayerQMI HealthLayer = "qmi"
	// HealthLayerMBIM MBIM 协议控制层（健康观测 + host 侧 reopen 恢复 + 超限重建兜底）
	HealthLayerMBIM HealthLayer = "mbim"
	// HealthLayerPool 设备池全局生命周期控制层
	HealthLayerPool HealthLayer = "pool"
)

// HealthState 标识设备当前的健康状态
type HealthState string

const (
	// HealthStateHealthy 设备完全健康且工作正常
	HealthStateHealthy HealthState = "healthy"
	// HealthStateSuspect 设备出现异常，处于可疑受限阶段
	HealthStateSuspect HealthState = "suspect"
	// HealthStateRecovering 设备处于自动故障恢复流程中
	HealthStateRecovering HealthState = "recovering"
	// HealthStateInvalid 设备已被判定为非法/不可用状态
	HealthStateInvalid HealthState = "invalid"
	// HealthStateReprobing 设备正在重新探测与握手初始化中
	HealthStateReprobing HealthState = "reprobing"
	// HealthStateFailed 设备已确认彻底故障，无法自动恢复
	HealthStateFailed HealthState = "failed"
)

// WatchdogEvent 记录一次健康看门狗检测到的状态变更事件
type WatchdogEvent struct {
	Layer               HealthLayer // 触发事件的协议分层
	State               HealthState // 事件关联的目标健康状态
	EventType           string      // 事件分类类型描述
	Reason              string      // 触发健康变动的深层原因
	Err                 error       // 关联的错误详情
	ConsecutiveFailures int         // 当前累计的连续失败次数
	Threshold           int         // 判定状态恶化的最大失败次数阈值
	RecoveryUntil       time.Time   // 故障恢复宽限期的截止时间戳
	At                  time.Time   // 事件发生的物理时间戳
}

// HealthSnapshot 存储对外展示的设备健康状态只读属性快照
type HealthSnapshot struct {
	State               HealthState // 总体健康状态
	Layer               HealthLayer // 触发异常的层级
	EventType           string      // 事件分类描述
	Reason              string      // 异常或变动的具体原因
	Error               string      // 错误详情字符串
	ConsecutiveFailures int         // 累计的连续失败次数
	Threshold           int         // 连续失败的阈值
	RecoveryUntil       time.Time   // 故障自动恢复流程的超时宽限时间
	UpdatedAt           time.Time   // 本次状态刷新时间
}

// RecordWatchdogEvent 线程安全地记录一次看门狗健康事件，更新 consecutive failures 计数器及缓存快照，并向 worker 状态投影层广播
func (w *Worker) RecordWatchdogEvent(event WatchdogEvent) HealthSnapshot {
	if w == nil {
		return HealthSnapshot{}
	}
	if event.At.IsZero() {
		event.At = time.Now()
	}
	if event.Layer == "" {
		event.Layer = HealthLayerPool
	}
	if event.State == "" {
		event.State = HealthStateSuspect
	}
	event.Reason = strings.TrimSpace(event.Reason)
	if event.Reason == "" {
		event.Reason = strings.TrimSpace(event.EventType)
	}

	snapshot := HealthSnapshot{
		State:               event.State,
		Layer:               event.Layer,
		EventType:           strings.TrimSpace(event.EventType),
		Reason:              event.Reason,
		ConsecutiveFailures: event.ConsecutiveFailures,
		Threshold:           event.Threshold,
		RecoveryUntil:       event.RecoveryUntil,
		UpdatedAt:           event.At,
	}
	if event.Err != nil {
		snapshot.Error = event.Err.Error()
	}

	w.healthMu.Lock()
	switch event.State {
	case HealthStateHealthy:
		w.healthConsecutiveFailures = 0
		w.healthGraceUntil = time.Time{}
	case HealthStateRecovering:
		w.healthConsecutiveFailures = 0
		if event.RecoveryUntil.After(w.healthGraceUntil) {
			w.healthGraceUntil = event.RecoveryUntil
		}
		snapshot.RecoveryUntil = w.healthGraceUntil
	case HealthStateSuspect, HealthStateInvalid:
		if event.ConsecutiveFailures > 0 {
			w.healthConsecutiveFailures = event.ConsecutiveFailures
		}
		snapshot.ConsecutiveFailures = w.healthConsecutiveFailures
		if event.RecoveryUntil.IsZero() {
			snapshot.RecoveryUntil = w.healthGraceUntil
		}
	default:
		if event.RecoveryUntil.IsZero() {
			snapshot.RecoveryUntil = w.healthGraceUntil
		}
	}
	w.healthSnapshot = snapshot
	w.healthMu.Unlock()

	w.cacheMu.Lock()
	switch event.State {
	case HealthStateHealthy:
		w.state.Meta.Healthy = true
	case HealthStateInvalid, HealthStateFailed:
		w.state.Meta.Healthy = false
	}
	w.cacheMu.Unlock()

	return snapshot
}

// HealthSnapshot 安全地读取并返回当前设备 Worker 的最新健康状况快照
func (w *Worker) HealthSnapshot() HealthSnapshot {
	if w == nil {
		return HealthSnapshot{}
	}
	w.healthMu.Lock()
	defer w.healthMu.Unlock()
	snapshot := w.healthSnapshot
	if snapshot.State == "" {
		snapshot.State = HealthStateHealthy
	}
	if snapshot.Layer == "" {
		snapshot.Layer = HealthLayerPool
	}
	if snapshot.RecoveryUntil.IsZero() {
		snapshot.RecoveryUntil = w.healthGraceUntil
	}
	if snapshot.ConsecutiveFailures == 0 {
		snapshot.ConsecutiveFailures = w.healthConsecutiveFailures
	}
	return snapshot
}
