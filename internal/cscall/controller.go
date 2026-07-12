package cscall

import (
	"context"
	"time"
)

// EventType 定义呼叫事件类型
type EventType string

const (
	// EventIncoming 收到来电事件
	EventIncoming EventType = "incoming"
	// EventDialing 正在拨号外呼事件
	EventDialing EventType = "dialing"
	// EventRinging 对方振铃事件
	EventRinging EventType = "ringing"
	// EventConnected 电话已接通事件
	EventConnected EventType = "connected"
	// EventHangup 电话挂断事件
	EventHangup EventType = "hangup"
)

// Event 表示一个呼叫状态变更事件
type Event struct {
	Type   EventType // 事件类型
	CallID string    // 呼叫唯一标识符
	Number string    // 对方电话号码
}

// CallRef 标识已发起呼叫的引用信息
type CallRef struct {
	ID     string // 呼叫 ID
	Number string // 呼出号码
}

// CallInfo 记录当前活跃的呼叫详细信息
type CallInfo struct {
	ID        string    // 呼叫 ID
	Number    string    // 电话号码
	Direction string    // 呼叫方向 (in:来电, out:去电)
	State     CallState // 呼叫状态
}

// HangupOptions 挂断操作的可选控制参数
type HangupOptions struct {
	SendModemSignal bool // 是否向模组发送挂断信令（有些情况只需本地清理状态）
}

// Controller 定义了电路域 (CS) 呼叫控制器的核心行为接口
type Controller interface {
	Start(ctx context.Context) error                                     // 启动控制器并监听模组事件
	Stop()                                                               // 停止控制器并释放相关资源
	Dial(ctx context.Context, number string) (CallRef, error)            // 发起一个新的外呼电话
	Answer(ctx context.Context, callID string) error                     // 接听当前的来电
	Hangup(ctx context.Context, callID string, opts HangupOptions) error // 挂断指定的呼叫
	GetCalls(ctx context.Context) ([]CallInfo, error)                    // 获取当前所有活跃的呼叫列表
	Events() <-chan Event                                                // 返回呼叫事件流的只读通道
	PCMReady() <-chan bool                                               // 返回 PCM 音频通道就绪状态的只读通道
}

// atModem 定义了与 AT 模组进行电路域语音交互的底层接口
type atModem interface {
	SetRingCallback(func())                                // 设置来电振铃 (RING) 的回调函数
	SetClipCallback(func(string))                          // 设置来电来电显示 (CLIP) 号码的回调函数
	SetHangupCallback(func())                              // 设置挂断/拆线的回调函数
	GetQPCMVChan() <-chan int                              // 获取 QPCMV PCM 连接状态变更的通道
	DialCall(string) error                                 // 发起 AT 拨号 (ATD)
	AnswerCall() error                                     // 接听电话 (ATA)
	HangupCall() error                                     // 挂断电话 (ATH)
	ExecuteATSilent(string, time.Duration) (string, error) // 静默执行 AT 命令并设置超时
}
