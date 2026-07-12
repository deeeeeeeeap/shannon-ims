package cscall

import (
	"context"
	"time"
)

// ATController 实现基于 AT 串口指令的呼叫控制器
type ATController struct {
	modem    atModem            // 底层 AT 模组接口
	events   chan Event         // 呼叫事件分发通道
	pcmReady chan bool          // PCM 音频就绪状态分发通道
	cancel   context.CancelFunc // 用于取消运行时监听的 Cancel 方法
}

// NewATController 创建并初始化一个 AT 呼叫控制器
func NewATController(m atModem) *ATController {
	return &ATController{
		modem:    m,
		events:   make(chan Event, 8),
		pcmReady: make(chan bool, 8),
	}
}

// Start 启动 AT 控制器，开始监听来电、挂断、来电显示等 AT 主动上报事件并监控 PCM 音频
func (c *ATController) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.modem.SetRingCallback(func() {
		c.emit(Event{Type: EventIncoming, CallID: "at", Number: "Unknown"})
	})
	c.modem.SetClipCallback(func(number string) {
		c.emit(Event{Type: EventIncoming, CallID: "at", Number: number})
	})
	c.modem.SetHangupCallback(func() {
		c.emit(Event{Type: EventHangup, CallID: "at"})
	})
	go c.monitorPCM(runCtx)
	return nil
}

// Stop 停止监听并注销控制器
func (c *ATController) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Dial 向指定的目标号码发起 AT 拨号，并返回对应的呼叫引用信息
func (c *ATController) Dial(ctx context.Context, number string) (CallRef, error) {
	if err := c.modem.DialCall(number); err != nil {
		return CallRef{}, err
	}
	return CallRef{ID: "at", Number: number}, nil
}

// Answer 接听当前的 AT 串口来电
func (c *ATController) Answer(ctx context.Context, callID string) error {
	return c.modem.AnswerCall()
}

// Hangup 挂断当前的 AT 呼叫。如果设置了 SendModemSignal，则发送挂断指令并关闭 PCM 通道
func (c *ATController) Hangup(ctx context.Context, callID string, opts HangupOptions) error {
	var hangupErr error
	if opts.SendModemSignal {
		hangupErr = c.modem.HangupCall()
	}
	_, _ = c.modem.ExecuteATSilent("AT+QPCMV=0", 2*time.Second)
	return hangupErr
}

// GetCalls 通过 AT+CLCC 指令查询当前活跃的呼叫状态并返回呼叫信息列表
func (c *ATController) GetCalls(ctx context.Context) ([]CallInfo, error) {
	resp, err := c.modem.ExecuteATSilent("AT+CLCC", 2*time.Second)
	if err != nil {
		return nil, err
	}
	if containsCLCCActive(resp) {
		return []CallInfo{{ID: "at", Direction: "out", State: CallStateConnected}}, nil
	}
	return nil, nil
}

// Events 获取呼叫事件的只读通道
func (c *ATController) Events() <-chan Event { return c.events }

// PCMReady 获取 PCM 就绪状态的只读通道
func (c *ATController) PCMReady() <-chan bool { return c.pcmReady }

// monitorPCM 在后台循环监控 PCM 的连接状态变化，并向外推送 PCM 状态变化事件
func (c *ATController) monitorPCM(ctx context.Context) {
	ch := c.modem.GetQPCMVChan()
	for {
		select {
		case <-ctx.Done():
			return
		case state, ok := <-ch:
			if !ok {
				return
			}
			c.emitPCM(state == 1)
		}
	}
}

// emit 辅助非阻塞地向事件通道发送事件，如果通道满则丢弃
func (c *ATController) emit(event Event) {
	select {
	case c.events <- event:
	default:
	}
}

// emitPCM 辅助非阻塞地向 PCM 就绪通道发送事件，如果通道满则丢弃
func (c *ATController) emitPCM(ready bool) {
	select {
	case c.pcmReady <- ready:
	default:
	}
}
