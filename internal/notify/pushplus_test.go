package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
)

const pushplusSimToken = "sim-token-0f1e2d"

// pushplusSim stands in for the PushPlus service: it keeps the requests it
// gets and answers them as answer says.
type pushplusSim struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []map[string]any
	types    []string
}

func startPushplusSim(t *testing.T, answer http.HandlerFunc) *pushplusSim {
	t.Helper()
	sim := &pushplusSim{}
	sim.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var request map[string]any
		_ = json.Unmarshal(body, &request)
		sim.mu.Lock()
		sim.requests = append(sim.requests, request)
		sim.types = append(sim.types, r.Method+" "+r.Header.Get("Content-Type"))
		sim.mu.Unlock()
		answer(w, r)
	}))
	t.Cleanup(sim.server.Close)
	return sim
}

func (s *pushplusSim) channel(t *testing.T, change func(*config.PushplusConfig)) *PushplusChannel {
	t.Helper()
	cfg := config.PushplusConfig{Enabled: true, Token: pushplusSimToken}
	if change != nil {
		change(&cfg)
	}
	ch, err := NewPushplusChannel(cfg)
	if err != nil {
		t.Fatalf("cannot make the channel: %v", err)
	}
	ch.endpoint = s.server.URL + "/send"
	return ch
}

func (s *pushplusSim) received() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.requests...)
}

func pushplusAnswer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestPushplusMessageIsHandedOverAsTheServiceExpects(t *testing.T) {
	sim := startPushplusSim(t, pushplusAnswer(http.StatusOK, `{"code":200,"msg":"请求成功","data":"serial"}`))
	ch := sim.channel(t, nil)

	err := ch.SendWithContext(NotificationContext{Event: "sms_received", Text: "你好", DeviceID: "dev-1", DeviceName: "设备A"})
	if err != nil {
		t.Fatalf("an accepted message was reported as failed: %v", err)
	}

	received := sim.received()
	if len(received) != 1 {
		t.Fatalf("the service got %d requests, want 1", len(received))
	}
	want := map[string]any{
		"token":    pushplusSimToken,
		"title":    "[Vohive] sms_received - 设备A (dev-1)",
		"content":  "你好",
		"template": "markdown",
		"channel":  "wechat",
	}
	if len(received[0]) != len(want) {
		t.Fatalf("request = %v, want %v", received[0], want)
	}
	for key, value := range want {
		if received[0][key] != value {
			t.Fatalf("request[%q] = %v, want %v", key, received[0][key], value)
		}
	}
	sim.mu.Lock()
	kind := sim.types[0]
	sim.mu.Unlock()
	if kind != "POST application/json" {
		t.Fatalf("request was %q, want a POST of JSON", kind)
	}
}

func TestPushplusTopicAndChannelFollowTheSettings(t *testing.T) {
	sim := startPushplusSim(t, pushplusAnswer(http.StatusOK, `{"code":200,"msg":"ok"}`))
	ch := sim.channel(t, func(cfg *config.PushplusConfig) {
		cfg.Topic = "family"
		cfg.Channel = "mail"
	})

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("an accepted message was reported as failed: %v", err)
	}
	received := sim.received()
	if len(received) != 1 || received[0]["topic"] != "family" || received[0]["channel"] != "mail" || received[0]["title"] != "[Vohive] 通知" {
		t.Fatalf("requests = %v", received)
	}
}

func TestPushplusRefusalAnsweredWithHTTP200IsReported(t *testing.T) {
	// The answer the service gave to a request without a token.
	sim := startPushplusSim(t, pushplusAnswer(http.StatusOK, `{"code":999,"data":"token不能为空","msg":"服务端验证错误"}`))
	ch := sim.channel(t, nil)

	err := ch.Send("hello")
	if err == nil {
		t.Fatal("a refused message was reported as sent")
	}
	if !strings.Contains(err.Error(), "code=999") || !strings.Contains(err.Error(), "服务端验证错误") {
		t.Fatalf("error = %v, want the code and the reason the service gave", err)
	}
	if strings.Contains(err.Error(), pushplusSimToken) {
		t.Fatalf("the error shows the token: %v", err)
	}
}

func TestPushplusAnswersThatDoNotTellAcceptanceAreFailures(t *testing.T) {
	for name, answer := range map[string]http.HandlerFunc{
		"server error":   pushplusAnswer(http.StatusInternalServerError, `{"code":200}`),
		"not JSON":       pushplusAnswer(http.StatusOK, `<html>maintenance</html>`),
		"no code":        pushplusAnswer(http.StatusOK, `{"msg":"ok"}`),
		"empty":          pushplusAnswer(http.StatusOK, ``),
		"long refusal":   pushplusAnswer(http.StatusOK, `{"code":500,"msg":"`+strings.Repeat("错", 500)+`"}`),
		"refusal, lines": pushplusAnswer(http.StatusOK, `{"code":500,"msg":"a\nb"}`),
	} {
		t.Run(name, func(t *testing.T) {
			sim := startPushplusSim(t, answer)
			err := sim.channel(t, nil).Send("hello")
			if err == nil {
				t.Fatal("the message was reported as sent")
			}
			if strings.Contains(err.Error(), "\n") || len([]rune(err.Error())) > 200 {
				t.Fatalf("the error is not one short line: %q", err.Error())
			}
		})
	}
}

func TestPushplusServerThatSaysNothingGivesUp(t *testing.T) {
	release := make(chan struct{})
	sim := startPushplusSim(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	ch := sim.channel(t, nil)
	ch.client.Timeout = 300 * time.Millisecond

	started := time.Now()
	err := ch.Send("hello")
	took := time.Since(started)

	if !isTimeout(err) {
		t.Fatalf("error = %v, want a timeout", err)
	}
	if took > 3*time.Second {
		t.Fatalf("gave up after %s, the limit is %s", took, ch.client.Timeout)
	}
}

func TestPushplusIsReachedEncryptedAndWithATimeLimit(t *testing.T) {
	ch, err := NewPushplusChannel(config.PushplusConfig{Enabled: true, Token: pushplusSimToken})
	if err != nil {
		t.Fatalf("cannot make the channel: %v", err)
	}
	if !strings.HasPrefix(ch.endpoint, "https://") {
		t.Fatalf("endpoint = %q; the token is part of every request", ch.endpoint)
	}
	if ch.client.Timeout <= 0 {
		t.Fatal("requests have no time limit")
	}
	if _, err := NewPushplusChannel(config.PushplusConfig{Enabled: true, Token: "  "}); err == nil {
		t.Fatal("a channel without a token was made")
	}
}
