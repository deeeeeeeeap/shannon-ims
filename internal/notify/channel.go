package notify

// CommandContext 传递命令上下文，使得异步操作可以精准回复本会话
type CommandContext interface {
	Reply(text string)
}

// CommandHandler 命令处理器，接收上下文及参数切片，返回回复文本
type CommandHandler func(cmdCtx CommandContext, args []string) string

// Channel 统一通知渠道接口
// 所有通知渠道（Telegram、飞书、未来的 Discord/Slack 等）均实现此接口
type Channel interface {
	// Name 返回渠道名称（如 "telegram"、"feishu"）
	Name() string

	// Send 发送文本消息
	Send(text string) error

	// RegisterCommand 注册命令处理器
	// cmd: 命令名（如 "send"），handler: 处理函数
	RegisterCommand(cmd string, handler CommandHandler)

	// Start 启动命令监听（阻塞式，应在 goroutine 中调用）
	Start() error

	// Close 释放资源，停止监听
	Close() error
}
