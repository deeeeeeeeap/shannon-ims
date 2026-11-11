package notify

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/1239t/vohive/internal/config"
)

func TestBarkFailureKeepsTheDeviceKeyOutOfLogAndError(t *testing.T) {
	target := unreachableURL(t) + "/" + urlPathSecret
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{target}})

	logged := logOfFailedBroadcast(t, ch)
	checkAbsent(t, "the log", logged, urlPathSecret)
	if !strings.Contains(logged, "http://127.0.0.1:") {
		t.Fatalf("the log does not tell which server failed:\n%s", logged)
	}

	result, err := ch.SendWithContextDetailed(NotificationContext{Event: "notification", Text: "hello"})
	if err == nil {
		t.Fatal("a request to a port nothing listens on was reported as delivered")
	}
	checkAbsent(t, "the error", err.Error(), urlPathSecret)
	// The caller that asked for the details is the one who entered the URLs.
	if want := []string{target}; !reflect.DeepEqual(result.FailedURLs, want) {
		t.Fatalf("failed URLs = %q, want %q", result.FailedURLs, want)
	}
}

func TestBarkRefusalKeepsTheDeviceKeyOutOfTheLog(t *testing.T) {
	sim := startBarkSim(t, http.StatusBadRequest)
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{sim.server.URL + "/" + urlPathSecret}})

	logged := logOfFailedBroadcast(t, ch)
	checkAbsent(t, "the log", logged, urlPathSecret)
	if !strings.Contains(logged, "Bark 推送返回错误状态码") {
		t.Fatalf("the refusal was not logged:\n%s", logged)
	}
}

func TestWebhookFailureKeepsTheURLSecretsOutOfLogAndError(t *testing.T) {
	target := unreachableURL(t) + "/hooks/" + urlPathSecret + "?key=" + urlQuerySecret
	ch, err := NewWebhookChannel(config.WebhookConfig{Enabled: true, URLs: []string{target}, RetryMax: 1})
	if err != nil || ch == nil {
		t.Fatalf("cannot make the channel: %v", err)
	}

	logged := logOfFailedBroadcast(t, ch)
	checkAbsent(t, "the log", logged, urlPathSecret, urlQuerySecret)
	if !strings.Contains(logged, "http://127.0.0.1:") {
		t.Fatalf("the log does not tell which server failed:\n%s", logged)
	}

	result, err := ch.SendWithContextDetailed(NotificationContext{Event: "notification", Text: "hello"})
	if err == nil {
		t.Fatal("a request to a port nothing listens on was reported as delivered")
	}
	checkAbsent(t, "the error", err.Error(), urlPathSecret, urlQuerySecret)
	if want := []string{target}; !reflect.DeepEqual(result.FailedURLs, want) {
		t.Fatalf("failed URLs = %q, want %q", result.FailedURLs, want)
	}
}

func TestTelegramMessageIsSentThroughTheConfiguredAddress(t *testing.T) {
	ch := newTelegramChannelForTest(t, startTelegramSim(t))
	if err := ch.Send("hello"); err != nil {
		t.Fatalf("the message was not sent: %v", err)
	}
}

func TestTelegramFailureKeepsTheBotTokenOutOfLogAndError(t *testing.T) {
	server := startTelegramSim(t)
	ch := newTelegramChannelForTest(t, server)
	server.Close()

	logged := logOfFailedBroadcast(t, ch)
	checkAbsent(t, "the log", logged, telegramSimSecret)
	if !strings.Contains(logged, "发送 telegram 消息失败") {
		t.Fatalf("the failure was not logged:\n%s", logged)
	}

	err := ch.Send("hello")
	if err == nil {
		t.Fatal("a message to a server that is gone was reported as sent")
	}
	checkAbsent(t, "the error", err.Error(), telegramSimSecret)
}

func TestTelegramProxyAccountIsNotLogged(t *testing.T) {
	logged := recordLog(t)
	// Nothing listens on the proxy port either: the bot cannot start, and
	// what was logged and returned on the way is what matters here.
	proxyAddress := strings.TrimPrefix(unreachableURL(t), "http://")
	proxy := "http://" + proxyUser + ":" + proxySecret + "@" + proxyAddress

	_, err := NewTelegramChannel(config.TelegramConfig{
		Enabled:  true,
		BotToken: telegramSimToken,
		ChatID:   1,
		BaseURL:  unreachableURL(t),
		Proxy:    proxy,
	})
	if err == nil {
		t.Fatal("a bot was started through a proxy nothing listens on")
	}
	checkAbsent(t, "the error", err.Error(), proxySecret, proxyUser, telegramSimSecret)

	entries := logged("Telegram Bot 使用代理")
	checkAbsent(t, "the log", entries, proxySecret, proxyUser)
	if !strings.Contains(entries, "http://"+proxyAddress) {
		t.Fatalf("the log does not tell which proxy is used:\n%s", entries)
	}
}
