package server

import (
	"sync/atomic"
)

// TrafficStats 流量统计
type TrafficStats struct {
	// 使用 atomic 保证并发安全
	BytesSent     int64 // 发送字节数 (上传)
	BytesReceived int64 // 接收字节数 (下载)
	Connections   int64 // 连接总数
	ActiveConns   int64 // 当前活跃连接数
}

// NewTrafficStats 创建流量统计器
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{}
}

// AddSent 增加发送流量
func (s *TrafficStats) AddSent(n int64) {
	atomic.AddInt64(&s.BytesSent, n)
}

// AddReceived 增加接收流量
func (s *TrafficStats) AddReceived(n int64) {
	atomic.AddInt64(&s.BytesReceived, n)
}

// IncrConnection 增加连接计数
func (s *TrafficStats) IncrConnection() {
	atomic.AddInt64(&s.Connections, 1)
	atomic.AddInt64(&s.ActiveConns, 1)
}

// DecrActiveConn 减少活跃连接
func (s *TrafficStats) DecrActiveConn() {
	atomic.AddInt64(&s.ActiveConns, -1)
}

// GetStats 获取统计快照
func (s *TrafficStats) GetStats() map[string]int64 {
	return map[string]int64{
		"bytes_sent":     atomic.LoadInt64(&s.BytesSent),
		"bytes_received": atomic.LoadInt64(&s.BytesReceived),
		"connections":    atomic.LoadInt64(&s.Connections),
		"active_conns":   atomic.LoadInt64(&s.ActiveConns),
	}
}

// Reset 重置统计
func (s *TrafficStats) Reset() {
	atomic.StoreInt64(&s.BytesSent, 0)
	atomic.StoreInt64(&s.BytesReceived, 0)
	atomic.StoreInt64(&s.Connections, 0)
	// 不重置活跃连接数
}

// FormatBytes 格式化字节数为可读字符串
func FormatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return formatFloat(float64(bytes)/GB) + " GB"
	case bytes >= MB:
		return formatFloat(float64(bytes)/MB) + " MB"
	case bytes >= KB:
		return formatFloat(float64(bytes)/KB) + " KB"
	default:
		return formatInt(bytes) + " B"
	}
}

func formatFloat(v float64) string {
	if v >= 100 {
		return formatInt(int64(v))
	}
	return sprintf("%.2f", v)
}

func formatInt(v int64) string {
	return sprintf("%d", v)
}

func sprintf(format string, a ...interface{}) string {
	// 简单实现，避免引入 fmt
	switch format {
	case "%.2f":
		f := a[0].(float64)
		i := int64(f * 100)
		return formatInt(i/100) + "." + formatInt(i%100/10) + formatInt(i%10)
	case "%d":
		return itoa(a[0].(int64))
	}
	return ""
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	if i < 0 {
		return "-" + itoa(-i)
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
