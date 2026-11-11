package notify

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"mime"
	"net/mail"
	"net/smtp"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
)

const (
	smtpSimUser     = "vohive"
	smtpSimPassword = "sim-password"
)

// emailChannelFor returns a channel that delivers to the simulator with the
// simulator's account, and gives up soon enough for a test.
func emailChannelFor(t *testing.T, sim *smtpSim, change func(*config.EmailConfig)) *EmailChannel {
	t.Helper()
	cfg := config.EmailConfig{
		Enabled:     true,
		UseSSL:      sim.ImplicitTLS,
		SMTPHost:    "127.0.0.1",
		SMTPPort:    sim.port(),
		Username:    sim.Username,
		Password:    sim.Password,
		FromAddress: "vohive@example.com",
		ToAddresses: []string{"first@example.com", "second@example.com"},
	}
	if change != nil {
		change(&cfg)
	}
	ch, err := NewEmailChannel(cfg)
	if err != nil {
		t.Fatalf("cannot make the channel: %v", err)
	}
	ch.tlsConfig = &tls.Config{RootCAs: sim.roots}
	ch.dialTimeout = 2 * time.Second
	ch.sendTimeout = 5 * time.Second
	return ch
}

// deliveredMail is a message as a mail reader sees it.
type deliveredMail struct {
	header  mail.Header
	subject string
	body    string
}

func readDeliveredMail(t *testing.T, raw string) deliveredMail {
	t.Helper()
	message, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("the message cannot be read: %v\n%s", err, raw)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(message.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("the subject cannot be decoded: %v", err)
	}
	if encoding := message.Header.Get("Content-Transfer-Encoding"); encoding != "base64" {
		t.Fatalf("Content-Transfer-Encoding = %q, want base64", encoding)
	}
	encoded, err := io.ReadAll(message.Body)
	if err != nil {
		t.Fatalf("the body cannot be read: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(string(encoded)))
	if err != nil {
		t.Fatalf("the body cannot be decoded: %v", err)
	}
	return deliveredMail{header: message.Header, subject: subject, body: string(body)}
}

// requireShortASCIILines fails unless every line of the message can pass any
// mail server: printable ASCII, and no longer than a line may be.
func requireShortASCIILines(t *testing.T, raw string) {
	t.Helper()
	for number, line := range strings.Split(strings.TrimSuffix(raw, "\r\n"), "\r\n") {
		if len(line) > emailBodyLineLength {
			t.Fatalf("line %d has %d characters, more than %d: %q", number+1, len(line), emailBodyLineLength, line)
		}
		for i := 0; i < len(line); i++ {
			if line[i] < ' ' || line[i] > '~' {
				t.Fatalf("line %d holds a byte that is not printable ASCII: %q", number+1, line)
			}
		}
	}
}

func requireOneMessage(t *testing.T, sim *smtpSim) smtpSimMessage {
	t.Helper()
	messages := sim.messages()
	if len(messages) != 1 {
		t.Fatalf("the server was handed %d messages, want 1", len(messages))
	}
	return messages[0]
}

func TestEmailIsDeliveredOverTLSWithTheAccount(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{
		ImplicitTLS: true,
		Mechanisms:  "PLAIN LOGIN",
		Username:    smtpSimUser,
		Password:    smtpSimPassword,
		RequireAuth: true,
	})
	ch := emailChannelFor(t, sim, nil)

	err := ch.SendWithContext(NotificationContext{
		Event:      "sms_received",
		Text:       "收到新短信\n设备  设备A\n内容  你好，world",
		DeviceID:   "dev-1",
		DeviceName: "设备A",
	})
	if err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}

	got := requireOneMessage(t, sim)
	if got.From != "vohive@example.com" {
		t.Fatalf("sender = %q", got.From)
	}
	if want := []string{"first@example.com", "second@example.com"}; !reflect.DeepEqual(got.To, want) {
		t.Fatalf("recipients = %q, want %q", got.To, want)
	}
	if !got.Encrypted || got.Mechanism != "PLAIN" {
		t.Fatalf("encrypted = %v, authenticated with %q; want an encrypted session authenticated with PLAIN", got.Encrypted, got.Mechanism)
	}

	requireShortASCIILines(t, got.Raw)
	delivered := readDeliveredMail(t, got.Raw)
	if want := "[Vohive] sms_received - 设备A (dev-1)"; delivered.subject != want {
		t.Fatalf("subject = %q, want %q", delivered.subject, want)
	}
	if want := "收到新短信\r\n设备  设备A\r\n内容  你好，world\r\n"; delivered.body != want {
		t.Fatalf("body = %q, want %q", delivered.body, want)
	}
	if _, err := delivered.header.Date(); err != nil {
		t.Fatalf("the date cannot be read: %v", err)
	}
	if id := delivered.header.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@example.com>") {
		t.Fatalf("Message-ID = %q", id)
	}
	if version := delivered.header.Get("MIME-Version"); version != "1.0" {
		t.Fatalf("MIME-Version = %q", version)
	}
	if contentType := delivered.header.Get("Content-Type"); contentType != "text/plain; charset=UTF-8" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	from, err := delivered.header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Address != "vohive@example.com" {
		t.Fatalf("From = %v (%v)", from, err)
	}
	to, err := delivered.header.AddressList("To")
	if err != nil || len(to) != 2 || to[0].Address != "first@example.com" || to[1].Address != "second@example.com" {
		t.Fatalf("To = %v (%v)", to, err)
	}
}

func TestEmailWithoutSSLIsUpgradedWithSTARTTLSWhenTheServerOffersIt(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{
		OfferSTARTTLS:     true,
		Mechanisms:        "PLAIN",
		AuthOnlyEncrypted: true,
		Username:          smtpSimUser,
		Password:          smtpSimPassword,
		RequireAuth:       true,
	})
	ch := emailChannelFor(t, sim, nil)

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	got := requireOneMessage(t, sim)
	if !got.Encrypted || got.Mechanism != "PLAIN" {
		t.Fatalf("encrypted = %v, authenticated with %q; want an upgraded session authenticated with PLAIN", got.Encrypted, got.Mechanism)
	}
	if delivered := readDeliveredMail(t, got.Raw); delivered.subject != "[Vohive] 通知" || delivered.body != "hello\r\n" {
		t.Fatalf("subject = %q, body = %q", delivered.subject, delivered.body)
	}
}

func TestEmailToAServerWithoutAuthenticationIsDeliveredWithoutIt(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, func(cfg *config.EmailConfig) {
		cfg.Username = smtpSimUser
		cfg.Password = smtpSimPassword
	})

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	if got := requireOneMessage(t, sim); got.Encrypted || got.Mechanism != "" {
		t.Fatalf("encrypted = %v, authenticated with %q; the server offers neither", got.Encrypted, got.Mechanism)
	}
}

func TestEmailUsesLOGINWhenTheServerDoesNotOfferPLAIN(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{
		ImplicitTLS: true,
		Mechanisms:  "LOGIN XOAUTH2",
		Username:    smtpSimUser,
		Password:    smtpSimPassword,
		RequireAuth: true,
	})
	ch := emailChannelFor(t, sim, nil)

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	if got := requireOneMessage(t, sim); got.Mechanism != "LOGIN" {
		t.Fatalf("authenticated with %q, want LOGIN", got.Mechanism)
	}
}

func TestEmailWithoutAUserNameDoesNotAuthenticate(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{
		ImplicitTLS: true,
		Mechanisms:  "PLAIN LOGIN",
		Username:    smtpSimUser,
		Password:    smtpSimPassword,
	})
	ch := emailChannelFor(t, sim, func(cfg *config.EmailConfig) {
		cfg.Username = ""
		cfg.Password = ""
	})

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	if got := requireOneMessage(t, sim); got.Mechanism != "" {
		t.Fatalf("authenticated with %q although no account is configured", got.Mechanism)
	}
}

func TestEmailWrongPasswordIsReported(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{
		ImplicitTLS: true,
		Mechanisms:  "PLAIN",
		Username:    smtpSimUser,
		Password:    smtpSimPassword,
		RequireAuth: true,
	})
	ch := emailChannelFor(t, sim, func(cfg *config.EmailConfig) {
		cfg.Password = "not-the-password"
	})

	err := ch.Send("hello")
	if err == nil || !strings.Contains(err.Error(), "认证失败") {
		t.Fatalf("error = %v, want one that tells the authentication failed", err)
	}
	if strings.Contains(err.Error(), "not-the-password") {
		t.Fatalf("the error shows the password: %v", err)
	}
	if messages := sim.messages(); len(messages) != 0 {
		t.Fatalf("the server was handed %d messages, want none", len(messages))
	}
}

func TestEmailRefusedRecipientIsReported(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{RefusedRecipient: "second@example.com"})
	ch := emailChannelFor(t, sim, nil)

	err := ch.Send("hello")
	if err == nil || !strings.Contains(err.Error(), "拒绝收件人") {
		t.Fatalf("error = %v, want one that tells a recipient was refused", err)
	}
	if messages := sim.messages(); len(messages) != 0 {
		t.Fatalf("the server was handed %d messages, want none", len(messages))
	}
}

func TestEmailToAServerThatSaysNothingGivesUp(t *testing.T) {
	for name, implicitTLS := range map[string]bool{"unencrypted": false, "TLS": true} {
		t.Run(name, func(t *testing.T) {
			sim := startSMTPSim(t, &smtpSim{ImplicitTLS: implicitTLS, Mute: true})
			ch := emailChannelFor(t, sim, nil)
			ch.sendTimeout = 300 * time.Millisecond

			started := time.Now()
			err := ch.Send("hello")
			took := time.Since(started)

			if !isTimeout(err) {
				t.Fatalf("error = %v, want a timeout", err)
			}
			if took > 3*time.Second {
				t.Fatalf("gave up after %s, the limit is %s", took, ch.sendTimeout)
			}
		})
	}
}

func TestEmailToAServerThatNeverConfirmsTheMessageGivesUp(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{ImplicitTLS: true, MuteAfterMessage: true})
	ch := emailChannelFor(t, sim, nil)
	ch.sendTimeout = 500 * time.Millisecond

	started := time.Now()
	err := ch.Send("hello")
	took := time.Since(started)

	if !isTimeout(err) {
		t.Fatalf("error = %v, want a timeout", err)
	}
	if took > 3*time.Second {
		t.Fatalf("gave up after %s, the limit is %s", took, ch.sendTimeout)
	}
}

func TestEmailToAPortNobodyListensOnFailsAtOnce(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, nil)
	sim.stop()

	started := time.Now()
	err := ch.Send("hello")
	took := time.Since(started)

	if err == nil || !strings.Contains(err.Error(), "连接邮件服务器失败") {
		t.Fatalf("error = %v, want one that tells the connection failed", err)
	}
	if took > time.Second {
		t.Fatalf("failed after %s; nothing was there to wait for", took)
	}
}

func TestEmailSubjectAndBodyOfAnyLengthGoOutInShortLines(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, nil)

	deviceName := strings.Repeat("测试设备", 25)
	lines := []string{
		"第一行",
		".一行以点开头",
		".",
		strings.Repeat("很长的一行 without any break ", 150),
		"",
		"last line",
	}
	text := strings.Join(lines, "\n")

	if err := ch.SendWithContext(NotificationContext{Event: "sms_received", Text: text, DeviceName: deviceName}); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	got := requireOneMessage(t, sim)
	requireShortASCIILines(t, got.Raw)
	delivered := readDeliveredMail(t, got.Raw)
	if want := "[Vohive] sms_received - " + deviceName; delivered.subject != want {
		t.Fatalf("subject = %q, want %q", delivered.subject, want)
	}
	if want := strings.Join(lines, "\r\n") + "\r\n"; delivered.body != want {
		t.Fatalf("the body is not what was sent: %d bytes, want %d", len(delivered.body), len(want))
	}
}

func TestEmailLongASCIISubjectGoesOutInShortLines(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, nil)

	deviceName := strings.Repeat("device-with-a-long-name ", 12) + "=?utf-8?q?not_a_word?="
	if err := ch.SendWithContext(NotificationContext{Event: "sms_received", Text: "hello", DeviceName: deviceName}); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	got := requireOneMessage(t, sim)
	requireShortASCIILines(t, got.Raw)
	if delivered, want := readDeliveredMail(t, got.Raw), "[Vohive] sms_received - "+deviceName; delivered.subject != want {
		t.Fatalf("subject = %q, want %q", delivered.subject, want)
	}
}

func TestEmailSubjectCannotAddHeaderFields(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, nil)

	err := ch.SendWithContext(NotificationContext{
		Event:      "sms_received",
		Text:       "hello",
		DeviceName: "dev\r\nBcc: someone@example.com\r\n\r\ninjected body",
	})
	if err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	got := requireOneMessage(t, sim)
	delivered := readDeliveredMail(t, got.Raw)
	if bcc := delivered.header.Get("Bcc"); bcc != "" {
		t.Fatalf("the device name added a header field: Bcc = %q", bcc)
	}
	if delivered.body != "hello\r\n" {
		t.Fatalf("body = %q, want what was sent", delivered.body)
	}
	if !strings.Contains(delivered.subject, "Bcc: someone@example.com") || strings.ContainsAny(delivered.subject, "\r\n") {
		t.Fatalf("subject = %q, want the device name on one line", delivered.subject)
	}
}

func TestEmailAddressesWrittenWithANameAreUnderstood(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{})
	ch := emailChannelFor(t, sim, func(cfg *config.EmailConfig) {
		cfg.FromAddress = "通知中心 <vohive@example.com>"
		cfg.ToAddresses = []string{"管理员 <first@example.com>", "  second@example.com ", " "}
	})

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not delivered: %v", err)
	}
	got := requireOneMessage(t, sim)
	if got.From != "vohive@example.com" {
		t.Fatalf("sender = %q", got.From)
	}
	if want := []string{"first@example.com", "second@example.com"}; !reflect.DeepEqual(got.To, want) {
		t.Fatalf("recipients = %q, want %q", got.To, want)
	}
	requireShortASCIILines(t, got.Raw)
	delivered := readDeliveredMail(t, got.Raw)
	from, err := delivered.header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Name != "通知中心" || from[0].Address != "vohive@example.com" {
		t.Fatalf("From = %v (%v)", from, err)
	}
	to, err := delivered.header.AddressList("To")
	if err != nil || len(to) != 2 || to[0].Name != "管理员" || to[1].Address != "second@example.com" {
		t.Fatalf("To = %v (%v)", to, err)
	}
}

func TestSMTPLoginGivesThePasswordOnlyToTheConfiguredServerOverTLS(t *testing.T) {
	newAuth := func() *smtpLoginAuth {
		return &smtpLoginAuth{username: smtpSimUser, password: smtpSimPassword, host: "mail.example.com"}
	}

	if _, _, err := newAuth().Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: false}); err == nil {
		t.Fatal("LOGIN started on an unencrypted connection to another machine")
	}
	if _, _, err := newAuth().Start(&smtp.ServerInfo{Name: "other.example.com", TLS: true}); err == nil {
		t.Fatal("LOGIN started with a server other than the configured one")
	}

	auth := newAuth()
	mechanism, initial, err := auth.Start(&smtp.ServerInfo{Name: "mail.example.com", TLS: true})
	if err != nil || mechanism != "LOGIN" || initial != nil {
		t.Fatalf("Start = %q, %q, %v", mechanism, initial, err)
	}
	if answer, err := auth.Next([]byte("Username:"), true); err != nil || string(answer) != smtpSimUser {
		t.Fatalf("first answer = %q, %v", answer, err)
	}
	if answer, err := auth.Next([]byte("Password:"), true); err != nil || string(answer) != smtpSimPassword {
		t.Fatalf("second answer = %q, %v", answer, err)
	}
	if _, err := auth.Next([]byte("More:"), true); err == nil {
		t.Fatal("a third question was answered")
	}
	if answer, err := newAuth().Next(nil, false); err != nil || answer != nil {
		t.Fatalf("answer after the server was done = %q, %v", answer, err)
	}

	local := &smtpLoginAuth{username: smtpSimUser, password: smtpSimPassword, host: "localhost"}
	if _, _, err := local.Start(&smtp.ServerInfo{Name: "localhost", TLS: false}); err != nil {
		t.Fatalf("LOGIN to this machine was refused: %v", err)
	}
}

func TestReloadIsNotHeldUpForEverByAMailServerThatSaysNothing(t *testing.T) {
	sim := startSMTPSim(t, &smtpSim{Mute: true})
	ch := emailChannelFor(t, sim, nil)
	ch.sendTimeout = 300 * time.Millisecond
	m := newTestNotifyManager(ch)

	m.broadcastWithContext(NotificationContext{Event: "notification", Text: "hello"})
	waitUntil(t, 5*time.Second, func() bool { return sim.connections() == 1 })

	reloaded := make(chan error, 1)
	go func() { reloaded <- m.UpdateConfig(&config.Config{}) }()
	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatalf("the reload failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reload is still waiting for the mail server")
	}
}
