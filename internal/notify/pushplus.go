package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/config"
)

const (
	// pushplusEndpoint 是服务的加密地址：每个请求都带着账号 token。
	pushplusEndpoint = "https://www.pushplus.plus/send"
	// pushplusTimeout 是单次请求的时限。不设时限的请求遇到不应答的服务器会一直等下去，
	// 而重新加载通知设置要等在途的请求结束。
	pushplusTimeout = 15 * time.Second
	// pushplusAccepted 是服务受理消息时应答里的 code。HTTP 状态码看不出拒绝：
	// 不带 token 的请求得到的是 HTTP 200 和 code 999。
	pushplusAccepted = 200

	pushplusAnswerLimit  = 64 << 10
	pushplusReasonLength = 120
)

type PushplusChannel struct {
	cfg      config.PushplusConfig
	endpoint string
	client   *http.Client
}

func NewPushplusChannel(cfg config.PushplusConfig) (*PushplusChannel, error) {
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, errors.New("pushplus token is required")
	}
	return &PushplusChannel{
		cfg:      cfg,
		endpoint: pushplusEndpoint,
		client:   &http.Client{Timeout: pushplusTimeout},
	}, nil
}

func (c *PushplusChannel) Name() string {
	return "pushplus"
}

func (c *PushplusChannel) Send(text string) error {
	return c.SendWithContext(NotificationContext{Event: "通知", Text: text})
}

func (c *PushplusChannel) SendWithContext(ctx NotificationContext) error {
	title := fmt.Sprintf("[Vohive] %s", ctx.Event)
	if label := ctx.DeviceLabel(); label != "未知设备" {
		title = fmt.Sprintf("[Vohive] %s - %s", ctx.Event, label)
	}

	payload := map[string]interface{}{
		"token":    c.cfg.Token,
		"title":    title,
		"content":  ctx.Text,
		"template": "markdown",
	}

	if c.cfg.Topic != "" {
		payload["topic"] = c.cfg.Topic
	}

	channel := c.cfg.Channel
	if channel == "" {
		channel = "wechat"
	}
	payload["channel"] = channel

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := c.client.Post(c.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("pushplus 请求失败: %w", err)
	}
	defer resp.Body.Close()
	answer, readErr := io.ReadAll(io.LimitReader(resp.Body, pushplusAnswerLimit))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pushplus 返回 HTTP %d", resp.StatusCode)
	}
	if readErr != nil {
		return fmt.Errorf("读取 pushplus 应答失败: %w", readErr)
	}
	var result struct {
		Code *int   `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.Unmarshal(answer, &result); err != nil || result.Code == nil {
		return errors.New("pushplus 应答无法识别")
	}
	if *result.Code != pushplusAccepted {
		reason := []rune(singleLine(result.Msg))
		if len(reason) > pushplusReasonLength {
			reason = reason[:pushplusReasonLength]
		}
		return fmt.Errorf("pushplus 拒绝了消息: code=%d %s", *result.Code, string(reason))
	}
	return nil
}

func (c *PushplusChannel) RegisterCommand(cmd string, handler CommandHandler) {
	// Pushplus 不支持接收指令
}

func (c *PushplusChannel) Start() error {
	return nil
}

func (c *PushplusChannel) Close() error {
	if c != nil && c.client != nil {
		c.client.CloseIdleConnections()
	}
	return nil
}
