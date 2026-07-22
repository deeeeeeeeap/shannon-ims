package notify

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/device"
	"github.com/1239t/vohive/pkg/logger"
)

// Manager 统一通知管理器
// 持有多个 Channel 实例，向所有已启用渠道广播通知和命令
type Manager struct {
	pool        *device.Pool
	lifecycleMu sync.Mutex
	channelsMu  sync.Mutex
	channelSet  *managedChannelSet
}

type managedChannelSet struct {
	channels []Channel
	sends    sync.WaitGroup
	starts   sync.WaitGroup
}

type NotificationContext struct {
	Event      string
	Text       string
	DeviceID   string
	DeviceName string
	Timestamp  time.Time
}

func (c NotificationContext) DeviceLabel() string {
	id := strings.TrimSpace(c.DeviceID)
	name := strings.TrimSpace(c.DeviceName)
	if name != "" && id != "" {
		return fmt.Sprintf("%s (%s)", name, id)
	}
	if name != "" {
		return name
	}
	if id != "" {
		return id
	}
	return "未知设备"
}

type contextualChannel interface {
	SendWithContext(ctx NotificationContext) error
}

// NewManager 根据配置创建通知管理器，初始化所有已启用的通知渠道
func NewManager(cfg *config.Config, pool *device.Pool) (*Manager, error) {
	m := &Manager{
		pool: pool,
	}

	set, err := m.buildChannelSet(cfg)
	if err != nil {
		return nil, err
	}
	m.channelSet = set
	m.startChannelSet(set)

	return m, nil
}

// buildChannelSet 根据配置创建一个尚未启动的不可变渠道集合。
func (m *Manager) buildChannelSet(cfg *config.Config) (*managedChannelSet, error) {
	channels := make([]Channel, 0, 7)
	cleanup := func() {
		for _, ch := range channels {
			_ = ch.Close()
		}
	}

	// Telegram 渠道
	if cfg.Telegram.Enabled {
		tg, err := NewTelegramChannel(cfg.Telegram)
		if err != nil {
			logger.Error("初始化 Telegram 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if tg != nil {
			channels = append(channels, tg)
		}
	}

	// 飞书渠道
	if cfg.Feishu.Enabled {
		fs, err := NewFeishuChannel(cfg.Feishu)
		if err != nil {
			logger.Error("初始化飞书渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if fs != nil {
			channels = append(channels, fs)
		}
	}

	// QQ 渠道
	if cfg.QQ.Enabled {
		qq, err := NewQQChannel(cfg.QQ)
		if err != nil {
			logger.Error("初始化 QQ 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if qq != nil {
			channels = append(channels, qq)
		}
	}

	// Webhook 渠道
	if cfg.Webhook.Enabled {
		wh, err := NewWebhookChannel(cfg.Webhook)
		if err != nil {
			logger.Error("初始化 Webhook 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if wh != nil {
			channels = append(channels, wh)
		}
	}

	// Bark 渠道
	if cfg.Bark.Enabled {
		bk, err := NewBarkChannel(cfg.Bark)
		if err != nil {
			logger.Error("初始化 Bark 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if bk != nil {
			channels = append(channels, bk)
		}
	}

	// Email 渠道
	if cfg.Email.Enabled {
		em, err := NewEmailChannel(cfg.Email)
		if err != nil {
			logger.Error("初始化 Email 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if em != nil {
			channels = append(channels, em)
		}
	}

	// Pushplus 渠道
	if cfg.Pushplus.Enabled {
		pp, err := NewPushplusChannel(cfg.Pushplus)
		if err != nil {
			logger.Error("初始化 Pushplus 渠道失败", "err", err)
			cleanup()
			return nil, err
		}
		if pp != nil {
			channels = append(channels, pp)
		}
	}

	// 向所有渠道注册命令
	m.registerCommands(channels)
	return &managedChannelSet{channels: channels}, nil
}

// registerCommands 向所有已启用渠道注册同一组命令处理器
func (m *Manager) registerCommands(channels []Channel) {
	commands := map[string]CommandHandler{
		"send":   m.handleCmdSendSMS,
		"status": m.handleCmdStatus,
		"rotate": m.handleCmdRotate,
		"list":   m.handleCmdList,
		"sms":    m.handleCmdSMSInbox,
		"esim":   m.handleCmdEsim,
		"switch": m.handleCmdSwitch,
		"vocall": m.handleCmdCall,
	}

	for _, ch := range channels {
		for cmd, handler := range commands {
			ch.RegisterCommand(cmd, handler)
		}
	}
}

func (m *Manager) startChannelSet(set *managedChannelSet) {
	if set == nil {
		return
	}
	for _, ch := range set.channels {
		ch := ch
		set.starts.Add(1)
		go func() {
			defer set.starts.Done()
			if err := ch.Start(); err != nil {
				logger.Error("通知渠道命令监听失败", "channel", ch.Name(), "err", err)
			}
		}()
	}
}

func (m *Manager) swapChannelSet(next *managedChannelSet) *managedChannelSet {
	m.channelsMu.Lock()
	old := m.channelSet
	m.channelSet = next
	m.channelsMu.Unlock()
	return old
}

func closeChannelSet(set *managedChannelSet) {
	if set == nil {
		return
	}
	set.sends.Wait()
	for _, ch := range set.channels {
		_ = ch.Close()
	}
	set.starts.Wait()
}

// Close 关闭所有通知渠道
func (m *Manager) Close() {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	closeChannelSet(m.swapChannelSet(nil))
}

// UpdateConfig 重新加载通知配置（热更新）
func (m *Manager) UpdateConfig(cfg *config.Config) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	next, err := m.buildChannelSet(cfg)
	if err != nil {
		return err
	}
	old := m.swapChannelSet(next)
	m.startChannelSet(next)
	closeChannelSet(old)
	return nil
}

// NotifySMS 实现 device.Notifier 接口 — 收到短信通知
func (m *Manager) NotifySMS(deviceID, sender, content string, timestamp time.Time) {
	m.NotifySMSWithSource(deviceID, sender, content, "蜂窝", timestamp)
}

func (m *Manager) NotifySMSWithSource(deviceID, sender, content, source string, timestamp time.Time) {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "蜂窝"
	}
	msg := fmt.Sprintf("收到新短信 / %s\n设备  %s\n号码  %s\n时间  %s\n内容  %s",
		source, deviceID, sender, timestamp.Format("2006-01-02 15:04:05"), content)

	logger.Info("开始发送短信通知",
		"event", "sms_received",
		"sms_device", deviceID,
		"source", source,
		"channel_count", m.channelCount())

	m.broadcastWithContext(NotificationContext{
		Event:      "sms_received",
		Text:       msg,
		DeviceID:   deviceID,
		DeviceName: m.resolveDeviceName(deviceID),
		Timestamp:  timestamp,
	})
}

// NotifyRaw 发送原始文本通知到所有渠道
func (m *Manager) NotifyRaw(msg string) {
	m.broadcastWithContext(NotificationContext{
		Event:     "raw",
		Text:      msg,
		Timestamp: time.Now(),
	})
}

// NotifyIPRotated 实现 device.Notifier 接口 — IP 切换通知
func (m *Manager) NotifyIPRotated(deviceID, oldIP, newIP string, duration time.Duration) {
	displayName := deviceID
	if m.pool != nil {
		if worker := m.pool.GetWorker(deviceID); worker != nil && worker.Config.Name != "" {
			displayName = fmt.Sprintf("%s (%s)", worker.Config.Name, deviceID)
		}
	}
	msg := fmt.Sprintf("公网切换 / 完成\n设备    %s\n旧 IP   %s\n新 IP   %s\n耗时    %s", displayName, oldIP, newIP, duration.String())
	m.broadcastWithContext(NotificationContext{
		Event:      "ip_rotated",
		Text:       msg,
		DeviceID:   deviceID,
		DeviceName: m.resolveDeviceName(deviceID),
		Timestamp:  time.Now(),
	})
}

// NotifyIncomingCall 实现 voice.CallNotifier 接口 — 来电通知
func (m *Manager) NotifyIncomingCall(deviceID, caller, callee string) {
	channelCount := m.channelCount()
	if channelCount == 0 {
		return
	}

	msg := fmt.Sprintf("来电通知\n设备    %s\n主叫    %s\n被叫    %s",
		deviceID, caller, callee)

	logger.Info("开始发送来电通知", "device", deviceID, "caller", caller, "channel_count", channelCount)

	m.broadcastWithContext(NotificationContext{
		Event:      "incoming_call",
		Text:       msg,
		DeviceID:   deviceID,
		DeviceName: m.resolveDeviceName(deviceID),
		Timestamp:  time.Now(),
	})
}

func (m *Manager) resolveDeviceName(deviceID string) string {
	if strings.TrimSpace(deviceID) == "" || m.pool == nil {
		return ""
	}
	worker := m.pool.GetWorker(deviceID)
	if worker == nil {
		return ""
	}
	return strings.TrimSpace(worker.Config.Name)
}

func (m *Manager) broadcastWithContext(ctx NotificationContext) {
	ctx.Text = strings.TrimSpace(ctx.Text)
	if ctx.Text == "" {
		return
	}
	if ctx.Timestamp.IsZero() {
		ctx.Timestamp = time.Now()
	}
	if strings.TrimSpace(ctx.Event) == "" {
		ctx.Event = "notification"
	}

	m.channelsMu.Lock()
	set := m.channelSet
	if set == nil || len(set.channels) == 0 {
		m.channelsMu.Unlock()
		return
	}
	channels := set.channels
	set.sends.Add(len(channels))
	m.channelsMu.Unlock()

	for _, ch := range channels {
		ch := ch // capture variable
		go func() {
			defer set.sends.Done()
			if withCtx, ok := ch.(contextualChannel); ok {
				if err := withCtx.SendWithContext(ctx); err != nil {
					logger.Warn("通知渠道发送失败", "channel", ch.Name(), "event", ctx.Event, "err", err)
				}
				return
			}
			if err := ch.Send(ctx.Text); err != nil {
				logger.Warn("通知渠道发送失败", "channel", ch.Name(), "event", ctx.Event, "err", err)
			}
		}()
	}
}

func (m *Manager) channelCount() int {
	m.channelsMu.Lock()
	defer m.channelsMu.Unlock()
	if m.channelSet == nil {
		return 0
	}
	return len(m.channelSet.channels)
}

// GetChannelNames 返回所有已启用渠道的名称列表
func (m *Manager) GetChannelNames() []string {
	m.channelsMu.Lock()
	set := m.channelSet
	if set == nil {
		m.channelsMu.Unlock()
		return nil
	}
	set.sends.Add(1)
	channels := set.channels
	m.channelsMu.Unlock()
	defer set.sends.Done()

	names := make([]string, 0, len(channels))
	for _, ch := range channels {
		names = append(names, ch.Name())
	}
	return names
}
