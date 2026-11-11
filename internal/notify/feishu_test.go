//go:build !(linux && arm)

package notify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"

	lark "github.com/larksuite/oapi-sdk-go/v3"
)

// feishuSim stands in for the Feishu open platform as far as sending a
// message needs it: it hands out an access token, keeps the messages it is
// asked to send and answers them as answer says.
type feishuSim struct {
	server *httptest.Server

	mu       sync.Mutex
	messages []feishuSimMessage
}

type feishuSimMessage struct {
	ReceiveIDType string
	Authorization string
	Body          map[string]any
}

func startFeishuSim(t *testing.T, answer http.HandlerFunc) *feishuSim {
	t.Helper()
	sim := &feishuSim{}
	mux := http.NewServeMux()
	mux.HandleFunc("/open-apis/auth/v3/tenant_access_token/internal", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"code":0,"msg":"ok","tenant_access_token":"t-sim","expire":7200}`)
	})
	mux.HandleFunc("/open-apis/im/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		message := feishuSimMessage{
			ReceiveIDType: r.URL.Query().Get("receive_id_type"),
			Authorization: r.Header.Get("Authorization"),
		}
		_ = json.Unmarshal(body, &message.Body)
		sim.mu.Lock()
		sim.messages = append(sim.messages, message)
		sim.mu.Unlock()
		answer(w, r)
	})
	sim.server = httptest.NewServer(mux)
	t.Cleanup(sim.server.Close)
	return sim
}

func (s *feishuSim) received() []feishuSimMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]feishuSimMessage(nil), s.messages...)
}

// The SDK keeps access tokens for the whole process by application: every
// channel of a test is an application of its own.
var feishuSimApplications atomic.Int64

func (s *feishuSim) channel(chatIDs ...string) *FeishuChannel {
	cfg := config.FeishuConfig{
		Enabled:   true,
		AppID:     fmt.Sprintf("cli_sim_%d", feishuSimApplications.Add(1)),
		AppSecret: "sim-secret",
	}
	return &FeishuChannel{
		client:   newFeishuAPIClient(cfg, lark.WithOpenBaseUrl(s.server.URL)),
		chatIDs:  chatIDs,
		handlers: make(map[string]CommandHandler),
		cfg:      cfg,
	}
}

func feishuAnswer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, body)
	}
}

func TestFeishuMessageIsSentToEveryChat(t *testing.T) {
	sim := startFeishuSim(t, feishuAnswer(`{"code":0,"msg":"success","data":{"message_id":"om_sim"}}`))
	ch := sim.channel("oc_first", "oc_second")

	if err := ch.Send("你好"); err != nil {
		t.Fatalf("the message was not sent: %v", err)
	}

	received := sim.received()
	if len(received) != 2 {
		t.Fatalf("the service was asked to send %d messages, want 2", len(received))
	}
	for i, chat := range []string{"oc_first", "oc_second"} {
		message := received[i]
		if message.ReceiveIDType != "chat_id" || message.Authorization != "Bearer t-sim" {
			t.Fatalf("message %d: receive_id_type = %q, Authorization = %q", i, message.ReceiveIDType, message.Authorization)
		}
		if message.Body["receive_id"] != chat || message.Body["msg_type"] != "text" || message.Body["content"] != `{"text":"你好"}` {
			t.Fatalf("message %d = %v", i, message.Body)
		}
	}
}

func TestFeishuRefusalIsReported(t *testing.T) {
	sim := startFeishuSim(t, feishuAnswer(`{"code":230002,"msg":"Bot/User can NOT be out of the chat."}`))
	ch := sim.channel("oc_first")

	err := ch.Send("hello")
	if err == nil || !strings.Contains(err.Error(), "230002") {
		t.Fatalf("error = %v, want the code the service gave", err)
	}
}

func TestFeishuWithoutAChatSendsNothing(t *testing.T) {
	sim := startFeishuSim(t, feishuAnswer(`{"code":0,"msg":"success","data":{}}`))

	if err := sim.channel().Send("hello"); err == nil {
		t.Fatal("a message without a chat to send it to was reported as sent")
	}
	if received := sim.received(); len(received) != 0 {
		t.Fatalf("the service was asked to send %d messages", len(received))
	}
}

func TestFeishuServiceThatSaysNothingGivesUp(t *testing.T) {
	limit := feishuRequestTimeout
	feishuRequestTimeout = 300 * time.Millisecond
	t.Cleanup(func() { feishuRequestTimeout = limit })

	release := make(chan struct{})
	sim := startFeishuSim(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	t.Cleanup(func() { close(release) })
	ch := sim.channel("oc_first")

	sent := make(chan error, 1)
	started := time.Now()
	go func() { sent <- ch.Send("hello") }()
	select {
	case err := <-sent:
		if err == nil {
			t.Fatal("a message the service never answered was reported as sent")
		}
		if took := time.Since(started); took > 5*time.Second {
			t.Fatalf("gave up after %s, the limit of a request is %s", took, feishuRequestTimeout)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the send is still waiting for the service")
	}
}
