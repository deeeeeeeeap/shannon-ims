package device

import "time"

// Notifier 定义了设备池需要的事件通知接口，
// 用于解耦具体的通知实现（如 Telegram 或 Webhook）
type Notifier interface {
	NotifySMS(deviceID, sender, content string, timestamp time.Time)
	NotifyIPRotated(deviceID, oldIP, newIP string, duration time.Duration)
	NotifyRaw(msg string)
}

type SMSSourceNotifier interface {
	NotifySMSWithSource(deviceID, sender, content, source string, timestamp time.Time)
}
