package swu

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/ikev2"
	"github.com/1239t/swu-go/pkg/logger"
)

// ErrWindowTimeout 当一个请求达到最大重试次数也没有收到相应的包时抛出
var ErrWindowTimeout = errors.New("timeout reached max retries")

// RetryConfig 重传退避配置
type RetryConfig struct {
	MaxRetries     int           // 最大重试次数
	InitialTimeout time.Duration // 初始超时时间
	MaxTimeout     time.Duration // 最大超时时间
	BackoffFactor  float64       // 退避因子
}

// DefaultRetryConfig 默认重传配置
// 对齐 strongSwan 默认值 (retransmit_timeout=4s, retransmit_base=1.8, retransmit_tries=5)
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxRetries:     5,
		InitialTimeout: 4 * time.Second,
		MaxTimeout:     0, // 0 表示无上限，与 strongSwan retransmit_limit=0 一致
		BackoffFactor:  1.8,
	}
}

// OutgoingMessage 承载发送队列中的单一请求包状态，对应一笔完整的事务交互
type OutgoingMessage struct {
	MsgID    uint32
	Payloads []ikev2.Payload
	Exchange ikev2.ExchangeType
	Packets  [][]byte // 已经构建和加密好的数据（多次重传可直接投递）

	// 重试上下文，与 strongSwan 退避算法对齐
	RetryCount  int
	MaxRetries  int
	NextTimeout time.Duration
	Deadline    time.Time

	// 信号通知通道：如果成功，把收到的解密包推入；如果彻底超时抛出 nil 关闭通道
	CompletionCh chan []byte
}

// TaskManager 用于接管原有的线性重试池，支撑滑动窗口概念 (Window Size)
type TaskManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	config *RetryConfig

	windowSize int
	pending    map[uint32]*OutgoingMessage // 正在窗口内飞行的请求
	queue      []*OutgoingMessage          // 因窗口已满排队等待排入的值

	mu       sync.Mutex
	wakeupCh chan struct{} // 用于有新包入列时唤醒内部守护循环
	done     chan struct{}

	sendFunc func([][]byte) error // 回拨底层的发包接口
}

func NewTaskManager(ctx context.Context, config *RetryConfig, winSize int, sendFunc func([][]byte) error) *TaskManager {
	if config == nil {
		config = DefaultRetryConfig()
	}
	if winSize < 1 {
		winSize = 1 // 兼容至少 1 个包的并发
	}

	tmCtx, cancel := context.WithCancel(ctx)

	tm := &TaskManager{
		ctx:        tmCtx,
		cancel:     cancel,
		config:     config,
		windowSize: winSize,
		pending:    make(map[uint32]*OutgoingMessage),
		queue:      make([]*OutgoingMessage, 0),
		wakeupCh:   make(chan struct{}, 1),
		done:       make(chan struct{}),
		sendFunc:   sendFunc,
	}

	// 启动后台重传与推包轮询
	go tm.windowLoop()
	return tm
}

func (tm *TaskManager) Stop() {
	tm.cancel()
	<-tm.done
}

func (tm *TaskManager) Done() <-chan struct{} { return tm.done }

// EnqueueRequest 将构筑好的包（可能是单包或者是多个 IKE 分片包）掷入调度器，返回接收通道
func (tm *TaskManager) EnqueueRequest(msgID uint32, exchange ikev2.ExchangeType, payloads []ikev2.Payload, packets [][]byte) <-chan []byte {
	outMsg := &OutgoingMessage{
		MsgID:        msgID,
		Payloads:     payloads,
		Exchange:     exchange,
		Packets:      packets,
		MaxRetries:   tm.config.MaxRetries,
		NextTimeout:  tm.config.InitialTimeout,
		CompletionCh: make(chan []byte, 1),
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// 检查当前飞行包是否达到窗口限制
	if len(tm.pending) < tm.windowSize {
		// 窗口富余，直接发射
		tm.activateMessage(outMsg)
	} else {
		// 进积压挂起队列等待
		tm.queue = append(tm.queue, outMsg)
	}

	return outMsg.CompletionCh
}

// 调度内部函数 (需加锁调用)
func (tm *TaskManager) activateMessage(msg *OutgoingMessage) {
	msg.Deadline = time.Now().Add(msg.NextTimeout)
	tm.pending[msg.MsgID] = msg

	// 首次推报
	if tm.sendFunc != nil {
		_ = tm.sendFunc(msg.Packets)
	}
	// 触发更新轮询
	select {
	case tm.wakeupCh <- struct{}{}:
	default:
	}
}

// HandleResponse 被解码器（IKE_Control）截获时调用，剥离其事务通道以反馈并接纳后续排队者
func (tm *TaskManager) HandleResponse(msgID uint32, responseData []byte) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	msg, ok := tm.pending[msgID]
	if !ok {
		return false
	}

	// 发出回执并清理
	delete(tm.pending, msgID)
	msg.CompletionCh <- responseData

	// 窗口腾出，检查排队区提取下一个候补
	tm.pumpQueue()
	return true
}

func (tm *TaskManager) pumpQueue() {
	if len(tm.queue) > 0 && len(tm.pending) < tm.windowSize {
		// 从队头推出
		nextMsgs := tm.queue[0]
		tm.queue = tm.queue[1:]

		logger.Debug("从 Pending 排队区释放延迟请求包", logger.Uint32("msgID", nextMsgs.MsgID))
		tm.activateMessage(nextMsgs)
	}
}

// windowLoop 后台重发机制死循环，处理重试超时惩罚与丢弃。替代了死板的 SendWithRetry。
func (tm *TaskManager) windowLoop() {
	defer close(tm.done)
	// 定时器触发频率，由于网络惩罚一般以秒为单位，0.5秒能满足大多数精度。
	const checkInterval = 500 * time.Millisecond
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			// 终止通知：清理所有频道
			tm.mu.Lock()
			for _, m := range tm.pending {
				close(m.CompletionCh)
			}
			for _, m := range tm.queue {
				close(m.CompletionCh)
			}
			tm.pending = make(map[uint32]*OutgoingMessage)
			tm.queue = nil
			tm.mu.Unlock()
			return
		case <-tm.wakeupCh:
			// 强制校验一次超时（如果新的发包刚好设定了新的边界）
			tm.checkTimeouts()
		case <-ticker.C:
			tm.checkTimeouts()
		}
	}
}

func (tm *TaskManager) checkTimeouts() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	var toDelete []uint32

	for id, msg := range tm.pending {
		if now.After(msg.Deadline) || now.Equal(msg.Deadline) {
			if msg.RetryCount >= msg.MaxRetries {
				// 已死，打捞并踢下线
				logger.Warn("IKE 请求遭遇硬超时，剔除 Window", logger.Uint32("msgID", id))
				toDelete = append(toDelete, id)
				close(msg.CompletionCh)
			} else {
				// 惩罚增长并执行再次空投
				msg.RetryCount++

				msg.NextTimeout = time.Duration(float64(msg.NextTimeout) * tm.config.BackoffFactor)
				if tm.config.MaxTimeout > 0 && msg.NextTimeout > tm.config.MaxTimeout {
					msg.NextTimeout = tm.config.MaxTimeout
				}
				msg.Deadline = now.Add(msg.NextTimeout)

				logger.Debug("IKE 请求触发滑动窗口重传",
					logger.Uint32("msgID", id),
					logger.Int("retry", msg.RetryCount),
					logger.Duration("nextDeadline", msg.NextTimeout))

				if tm.sendFunc != nil {
					_ = tm.sendFunc(msg.Packets)
				}
			}
		}
	}

	for _, id := range toDelete {
		delete(tm.pending, id)
	}
	if len(toDelete) > 0 {
		tm.pumpQueue()
	}
}
