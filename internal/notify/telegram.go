package notify

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/pkg/logger"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// TelegramChannel 实现 Channel 接口的 Telegram 通知渠道
type TelegramChannel struct {
	api      *tgbotapi.BotAPI
	chatID   int64
	handlers map[string]CommandHandler
}

// NewTelegramChannel 根据配置创建 Telegram 渠道
func NewTelegramChannel(cfg config.TelegramConfig) (*TelegramChannel, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	endpoint := tgbotapi.APIEndpoint
	if cfg.BaseURL != "" {
		endpoint = cfg.BaseURL
		if !strings.Contains(endpoint, "bot%s/%s") {
			endpoint = strings.TrimSuffix(endpoint, "/") + "/bot%s/%s"
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Proxy != "" {
		// 代理地址里可能带用户名和密码。
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			logger.Error("解析 Telegram 代理地址失败", "proxy", loggableURL(cfg.Proxy), "err", loggableError(err))
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
			logger.Info("Telegram Bot 使用代理", "proxy", loggableURL(cfg.Proxy))
		}
	}
	telegramLibraryLogOnce.Do(func() {
		_ = tgbotapi.SetLogger(telegramLibraryReports)
	})

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   120 * time.Second,
	}

	bot, err := tgbotapi.NewBotAPIWithClient(cfg.BotToken, endpoint, httpClient)
	if err != nil {
		msg := err.Error()
		if cfg.BotToken != "" {
			msg = strings.ReplaceAll(msg, cfg.BotToken, "<redacted>")
		}
		return nil, fmt.Errorf("创建 telegram bot 失败: %s", msg)
	}

	logger.Info("已授权账户 (TG)", "username", bot.Self.UserName)

	return &TelegramChannel{
		api:      bot,
		chatID:   cfg.ChatID,
		handlers: make(map[string]CommandHandler),
	}, nil
}

func (t *TelegramChannel) Name() string { return "telegram" }

func buildTelegramTextMessage(chatID int64, text string) tgbotapi.MessageConfig {
	// 过滤非法的 UTF-8 字符，防止 Telegram API 报错
	cleanText := strings.Map(func(r rune) rune {
		if r == utf8.RuneError {
			return -1 // 丢弃非法字符
		}
		return r
	}, text)

	escaped := html.EscapeString(cleanText)
	msg := tgbotapi.NewMessage(chatID, escaped)
	// 使用 HTML 模式，但先转义短信原文，避免 "<#>" 等内容被当作标签解析。
	msg.ParseMode = "HTML"
	return msg
}

func (t *TelegramChannel) Send(text string) error {
	if t == nil || t.api == nil {
		return nil
	}

	msg := buildTelegramTextMessage(t.chatID, text)
	_, err := t.api.Send(msg)
	if err != nil {
		// bot token 是请求 URL 的一部分，网络层失败的请求会在错误里带上这个 URL。
		err = loggableError(err)
		logger.Error("发送 telegram 消息失败", "err", err)
		return err
	}
	return nil
}

var (
	telegramLibraryLogOnce sync.Once
	// telegramLibraryReports 的输出位置和格式与库自带的默认日志相同：
	// 标准错误，带日期和时间。
	telegramLibraryReports = telegramLibraryLog{out: log.New(os.Stderr, "", log.LstdFlags)}
)

// telegramLibraryLog 是 Telegram 客户端库输出日志的去处。它去掉 bot token：
// 库会打印每一次失败的轮询，而网络层失败的请求其错误里带着请求 URL。
type telegramLibraryLog struct {
	out *log.Logger
}

func (l telegramLibraryLog) Println(v ...interface{}) {
	l.out.Print(scrubTelegramToken(fmt.Sprintln(v...)))
}

func (l telegramLibraryLog) Printf(format string, v ...interface{}) {
	l.out.Print(scrubTelegramToken(fmt.Sprintf(format, v...)))
}

func (t *TelegramChannel) RegisterCommand(cmd string, handler CommandHandler) {
	if t == nil {
		return
	}
	t.handlers[cmd] = handler
	logger.Info("注册 Telegram 命令", "command", "/"+cmd)
}

// tgCommandContext 实现了 CommandContext 接口
type tgCommandContext struct {
	channel *TelegramChannel
}

func (c *tgCommandContext) Reply(text string) {
	if c == nil || c.channel == nil {
		return
	}
	// 避免 Telegram API 短时阻塞拖住命令处理主循环
	go func() {
		_ = c.channel.Send(text)
	}()
}

// Start 启动 Telegram long-polling 命令监听（阻塞式）
func (t *TelegramChannel) Start() error {
	if t == nil || t.api == nil {
		return nil
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := t.api.GetUpdatesChan(u)
	logger.Info("Telegram Bot 命令监听已启动")

	for update := range updates {
		if update.Message == nil || !update.Message.IsCommand() {
			continue
		}

		// 仅处理来自授权用户的命令
		if update.Message.Chat.ID != t.chatID {
			continue
		}

		command := update.Message.Command()
		args := strings.Fields(update.Message.CommandArguments())

		logger.Info("收到 Telegram 命令", "command", command, "args", args)

		handler, ok := t.handlers[command]
		if !ok {
			ctx := &tgCommandContext{channel: t}
			ctx.Reply(unknownCommandReply(command))
			continue
		}

		ctx := &tgCommandContext{channel: t}
		response := handler(ctx, args)
		if response != "" {
			ctx.Reply(response)
		}
	}
	return nil
}

func (t *TelegramChannel) Close() error {
	if t == nil || t.api == nil {
		return nil
	}
	t.api.StopReceivingUpdates()
	return nil
}
