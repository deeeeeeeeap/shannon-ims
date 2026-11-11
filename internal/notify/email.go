package notify

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/1239t/vohive/internal/config"
)

const (
	// emailDialTimeout 是建立连接的时限，emailSendTimeout 是整次投递（含建立连接）
	// 的时限。不设时限的投递遇到接受连接后不再应答的服务器会一直等下去，而重新加载
	// 通知设置要等在途的投递结束。
	emailDialTimeout = 10 * time.Second
	emailSendTimeout = 30 * time.Second

	// emailBodyLineLength 是正文编码后每行的长度（RFC 2045），emailHeaderLineLength
	// 是含编码词的头部行允许的最大长度（RFC 2047）。
	emailBodyLineLength   = 76
	emailHeaderLineLength = 76

	encodedWordStart = "=?UTF-8?B?"
	encodedWordEnd   = "?="
)

type EmailChannel struct {
	cfg config.EmailConfig

	dialTimeout time.Duration
	sendTimeout time.Duration
	// tlsConfig 替换默认的 TLS 设置。测试用它来信任自己服务器的证书。
	tlsConfig *tls.Config
	now       func() time.Time
}

func NewEmailChannel(cfg config.EmailConfig) (*EmailChannel, error) {
	if cfg.SMTPHost == "" || cfg.SMTPPort == 0 || cfg.FromAddress == "" || len(cfg.ToAddresses) == 0 {
		return nil, errors.New("email configuration is incomplete")
	}
	return &EmailChannel{
		cfg:         cfg,
		dialTimeout: emailDialTimeout,
		sendTimeout: emailSendTimeout,
		now:         time.Now,
	}, nil
}

func (c *EmailChannel) Name() string {
	return "email"
}

func (c *EmailChannel) Send(text string) error {
	return c.SendWithContext(NotificationContext{Event: "通知", Text: text})
}

// SendWithContext 把一封邮件投递给所有配置的收件人。开启 use_ssl 时连接从一开始就加密；
// 未开启时，服务器提供 STARTTLS 就升级为加密连接。配置了用户名且服务器提供认证时
// 才使用账号。
func (c *EmailChannel) SendWithContext(ctx NotificationContext) error {
	from := envelopeAddress(c.cfg.FromAddress)
	recipients := make([]string, 0, len(c.cfg.ToAddresses))
	for _, to := range c.cfg.ToAddresses {
		if address := envelopeAddress(to); address != "" {
			recipients = append(recipients, address)
		}
	}
	if from == "" || len(recipients) == 0 {
		return errors.New("email configuration is incomplete")
	}
	return c.deliver(from, recipients, c.buildMessage(ctx, from))
}

func (c *EmailChannel) deliver(from string, recipients []string, message []byte) error {
	host := c.cfg.SMTPHost
	deadline := time.Now().Add(c.sendTimeout)

	dialer := &net.Dialer{Timeout: c.dialTimeout, Deadline: deadline}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(c.cfg.SMTPPort)))
	if err != nil {
		return fmt.Errorf("连接邮件服务器失败: %w", err)
	}
	defer conn.Close()
	// 后面所有步骤共用一个截止时间：对话的每一步都要等服务器应答。
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("连接邮件服务器失败: %w", err)
	}

	if c.cfg.UseSSL {
		secured := tls.Client(conn, c.tlsClientConfig())
		if err := secured.Handshake(); err != nil {
			return fmt.Errorf("邮件服务器 TLS 握手失败: %w", err)
		}
		conn = secured
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("邮件服务器未正常应答: %w", err)
	}
	defer client.Close()

	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("邮件服务器拒绝问候: %w", err)
	}
	if !c.cfg.UseSSL {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(c.tlsClientConfig()); err != nil {
				return fmt.Errorf("邮件服务器 STARTTLS 失败: %w", err)
			}
		}
	}
	if c.cfg.Username != "" {
		if ok, mechanisms := client.Extension("AUTH"); ok {
			if err := client.Auth(c.auth(mechanisms)); err != nil {
				return fmt.Errorf("邮件服务器认证失败: %w", err)
			}
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("邮件服务器拒绝发件人: %w", err)
	}
	for _, to := range recipients {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("邮件服务器拒绝收件人: %w", err)
		}
	}
	body, err := client.Data()
	if err != nil {
		return fmt.Errorf("邮件服务器拒绝接收邮件内容: %w", err)
	}
	if _, err := body.Write(message); err != nil {
		return fmt.Errorf("发送邮件内容失败: %w", err)
	}
	if err := body.Close(); err != nil {
		return fmt.Errorf("邮件服务器未接受邮件: %w", err)
	}
	// 服务器已经收下邮件；会话怎么结束不影响结果。
	_ = client.Quit()
	return nil
}

func (c *EmailChannel) tlsClientConfig() *tls.Config {
	cfg := &tls.Config{}
	if c.tlsConfig != nil {
		cfg = c.tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = c.cfg.SMTPHost
	}
	return cfg
}

// auth 为配置的账号选择认证方式：用 PLAIN，除非服务器提供 LOGIN 而不提供 PLAIN。
func (c *EmailChannel) auth(advertised string) smtp.Auth {
	plain, login := false, false
	for _, mechanism := range strings.Fields(advertised) {
		switch strings.ToUpper(mechanism) {
		case "PLAIN":
			plain = true
		case "LOGIN":
			login = true
		}
	}
	if login && !plain {
		return &smtpLoginAuth{username: c.cfg.Username, password: c.cfg.Password, host: c.cfg.SMTPHost}
	}
	return smtp.PlainAuth("", c.cfg.Username, c.cfg.Password, c.cfg.SMTPHost)
}

// smtpLoginAuth 是 net/smtp 没有提供的 LOGIN 认证方式：服务器先要用户名，再要密码。
type smtpLoginAuth struct {
	username string
	password string
	host     string
	asked    int
}

func (a *smtpLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// 条件与 net/smtp 的 PLAIN 相同：密码在线路上是可读的，所以只在 TLS 连接上或
	// 发往本机时才发送，并且只发给配置的服务器。
	if !server.TLS && !isLocalSMTPHost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *smtpLoginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.asked++
	switch a.asked {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	}
	return nil, errors.New("unexpected server challenge")
}

func isLocalSMTPHost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

// buildMessage 返回线路上传输的邮件。主题和正文通常不是 ASCII，所以主题写成 RFC 2047
// 的编码词，正文用 base64 并按允许的行长折行。
func (c *EmailChannel) buildMessage(ctx NotificationContext, from string) []byte {
	subject := fmt.Sprintf("[Vohive] %s", ctx.Event)
	if label := ctx.DeviceLabel(); label != "未知设备" {
		subject = fmt.Sprintf("[Vohive] %s - %s", ctx.Event, label)
	}
	recipients := make([]string, 0, len(c.cfg.ToAddresses))
	for _, to := range c.cfg.ToAddresses {
		if address := headerAddress(to); address != "" {
			recipients = append(recipients, address)
		}
	}

	var b strings.Builder
	header := func(name, value string) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\r\n")
	}
	header("From", headerAddress(c.cfg.FromAddress))
	header("To", strings.Join(recipients, ",\r\n "))
	header("Subject", headerText("Subject", subject))
	header("Date", c.now().Format(time.RFC1123Z))
	header("Message-ID", newMessageID(from))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=UTF-8")
	header("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")

	text := strings.ReplaceAll(ctx.Text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n") + "\r\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(text))
	for len(encoded) > emailBodyLineLength {
		b.WriteString(encoded[:emailBodyLineLength])
		b.WriteString("\r\n")
		encoded = encoded[emailBodyLineLength:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return []byte(b.String())
}

// envelopeAddress 返回配置的发件人或收件人的纯地址，配置里可以带显示名。
func envelopeAddress(configured string) string {
	if parsed, err := mail.ParseAddress(configured); err == nil {
		return parsed.Address
	}
	return strings.TrimSpace(configured)
}

// headerAddress 返回配置的发件人或收件人在邮件头里的写法：非 ASCII 的显示名会被编码。
func headerAddress(configured string) string {
	if parsed, err := mail.ParseAddress(configured); err == nil {
		return parsed.String()
	}
	return singleLine(configured)
}

// headerText 返回自由文本作为头部字段 name 的值：短的可打印 ASCII 原样返回，
// 否则写成编码词（RFC 2047），每行一个，每行都不超过允许的长度。
func headerText(name, text string) string {
	text = singleLine(text)
	used := len(name) + len(": ")
	if isPlainHeaderText(text) && used+len(text) <= emailHeaderLineLength {
		return text
	}
	var b strings.Builder
	for len(text) > 0 {
		// 这一行除去编码词的外框后还能放下的原文字节数：四个字符承载三个字节。
		room := (emailHeaderLineLength - used - len(encodedWordStart) - len(encodedWordEnd)) / 4 * 3
		cut := len(text)
		if cut > room {
			cut = room
			for cut > 0 && !utf8.RuneStart(text[cut]) {
				cut--
			}
			if cut <= 0 {
				_, cut = utf8.DecodeRuneInString(text)
			}
		}
		if b.Len() > 0 {
			b.WriteString("\r\n ")
		}
		b.WriteString(encodedWordStart)
		b.WriteString(base64.StdEncoding.EncodeToString([]byte(text[:cut])))
		b.WriteString(encodedWordEnd)
		text = text[cut:]
		used = len(" ")
	}
	return b.String()
}

// isPlainHeaderText 判断 text 能否原样放进头部字段。
func isPlainHeaderText(text string) bool {
	for i := 0; i < len(text); i++ {
		if text[i] < ' ' || text[i] > '~' {
			return false
		}
	}
	// 看起来像编码词开头的内容会被当成编码词解析。
	return !strings.Contains(text, "=?")
}

// singleLine 返回去掉了会结束当前头部字段或另起一个字段的字符后的 text。
func singleLine(text string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, text))
}

func newMessageID(from string) string {
	domain := "localhost"
	if at := strings.LastIndexByte(from, '@'); at >= 0 && at < len(from)-1 {
		domain = from[at+1:]
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Sprintf("<%d@%s>", time.Now().UnixNano(), domain)
	}
	return "<" + hex.EncodeToString(id) + "@" + domain + ">"
}

func (c *EmailChannel) RegisterCommand(cmd string, handler CommandHandler) {
	// 邮件渠道不支持接收指令
}

func (c *EmailChannel) Start() error {
	return nil
}

func (c *EmailChannel) Close() error {
	return nil
}
