package notify

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// 好几个渠道的地址里带着凭据：Bark 的设备密钥和 Telegram 的 bot token 在路径里，
// Webhook 地址的路径或查询参数里常带 token，代理地址里可能带用户名和密码。请求失败时
// 错误文本会带上请求的 URL，所以这类 URL 和这类错误都不能原样写进日志，也不能原样
// 返回给会把它写进日志的调用方。

// telegramTokenInURL 匹配 Telegram API 地址路径里的 bot token。
var telegramTokenInURL = regexp.MustCompile(`/bot[0-9]+:[A-Za-z0-9_-]+`)

const (
	redactedURLRemainder  = "/[redacted]"
	redactedTelegramToken = "/bot[redacted]"
	unreadableURL         = "[url]"
)

// loggableURL 返回 rawURL 里能说明是哪个服务、又不可能带凭据的部分：协议和主机。
// 主机之后的内容换成一个标记；用户名和密码去掉。
func loggableURL(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return unreadableURL
	}
	base := u.Scheme + "://" + u.Host
	if (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" {
		return base
	}
	return base + redactedURLRemainder
}

// loggableError 返回 err，其中所报告请求的 URL 按 loggableURL 处理。直接来自 HTTP
// 客户端的错误保留类型和原因；包了一层的错误只保留文本。
func loggableError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) || urlErr.URL == "" {
		return withoutTelegramToken(err)
	}
	if direct, ok := err.(*url.Error); ok {
		return &url.Error{Op: direct.Op, URL: loggableURL(direct.URL), Err: direct.Err}
	}
	// 这类错误的文本里 URL 带引号，引号里有些字符的写法不同。
	safe := loggableURL(urlErr.URL)
	text := strings.ReplaceAll(err.Error(), strconv.Quote(urlErr.URL), strconv.Quote(safe))
	text = strings.ReplaceAll(text, urlErr.URL, safe)
	return errors.New(scrubTelegramToken(text))
}

// withoutTelegramToken 返回文本里不带 Telegram bot token 的 err。
func withoutTelegramToken(err error) error {
	text := err.Error()
	clean := scrubTelegramToken(text)
	if clean == text {
		return err
	}
	return errors.New(clean)
}

func scrubTelegramToken(text string) string {
	return telegramTokenInURL.ReplaceAllString(text, redactedTelegramToken)
}
