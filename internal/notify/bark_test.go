package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
)

// barkSim stands in for a Bark server: it keeps the requests it gets and
// answers each of them with status.
type barkSim struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []barkSimRequest
}

type barkSimRequest struct {
	Path        string
	ContentType string
	Payload     map[string]any
}

func startBarkSim(t *testing.T, status int) *barkSim {
	t.Helper()
	sim := &barkSim{}
	sim.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		request := barkSimRequest{Path: r.URL.Path, ContentType: r.Header.Get("Content-Type")}
		_ = json.Unmarshal(body, &request.Payload)
		sim.mu.Lock()
		sim.requests = append(sim.requests, request)
		sim.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(sim.server.Close)
	return sim
}

func (s *barkSim) received() []barkSimRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]barkSimRequest(nil), s.requests...)
}

func newBarkChannelForTest(t *testing.T, cfg config.BarkConfig) *BarkChannel {
	t.Helper()
	cfg.Enabled = true
	ch, err := NewBarkChannel(cfg)
	if err != nil || ch == nil {
		t.Fatalf("cannot make the channel: %v", err)
	}
	return ch
}

func TestBarkDeliversToEveryURL(t *testing.T) {
	first := startBarkSim(t, http.StatusOK)
	second := startBarkSim(t, http.StatusOK)
	ch := newBarkChannelForTest(t, config.BarkConfig{
		URLs:  []string{first.server.URL + "/key-of-the-first", second.server.URL + "/key-of-the-second"},
		Group: " vohive ",
		Icon:  "https://example.com/icon.png",
		Level: "timeSensitive",
	})

	result, err := ch.SendWithContextDetailed(NotificationContext{Event: "sms_received", Text: "  你好  ", DeviceName: "设备A"})
	if err != nil || len(result.FailedURLs) != 0 {
		t.Fatalf("delivery failed: %v, failed URLs %q", err, result.FailedURLs)
	}

	wantPayload := map[string]any{
		"title": "💬 设备A",
		"body":  "你好",
		"group": "vohive",
		"icon":  "https://example.com/icon.png",
		"level": "timeSensitive",
	}
	for path, sim := range map[string]*barkSim{"/key-of-the-first": first, "/key-of-the-second": second} {
		received := sim.received()
		if len(received) != 1 {
			t.Fatalf("%s got %d requests, want 1", path, len(received))
		}
		if received[0].Path != path || received[0].ContentType != "application/json; charset=utf-8" {
			t.Fatalf("request = %+v", received[0])
		}
		if !reflect.DeepEqual(received[0].Payload, wantPayload) {
			t.Fatalf("payload = %v, want %v", received[0].Payload, wantPayload)
		}
	}
}

func TestBarkTitleFallsBackWhenTheDeviceIsUnknown(t *testing.T) {
	sim := startBarkSim(t, http.StatusOK)
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{sim.server.URL + "/key"}})

	if err := ch.Send("hello"); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	received := sim.received()
	if len(received) != 1 {
		t.Fatalf("got %d requests, want 1", len(received))
	}
	want := map[string]any{"title": "Vohive Notification", "body": "hello"}
	if !reflect.DeepEqual(received[0].Payload, want) {
		t.Fatalf("payload = %v, want %v", received[0].Payload, want)
	}
}

func TestBarkReportsTheURLsThatFailed(t *testing.T) {
	working := startBarkSim(t, http.StatusOK)
	broken := startBarkSim(t, http.StatusInternalServerError)
	brokenURL := broken.server.URL + "/key-of-the-broken"
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{working.server.URL + "/key", brokenURL}})

	result, err := ch.SendWithContextDetailed(NotificationContext{Event: "notification", Text: "hello"})
	if err == nil {
		t.Fatal("a refused request was reported as delivered")
	}
	if want := []string{brokenURL}; !reflect.DeepEqual(result.FailedURLs, want) {
		t.Fatalf("failed URLs = %q, want %q", result.FailedURLs, want)
	}
	if len(working.received()) != 1 {
		t.Fatal("the working server did not get the message")
	}
}

func TestBarkWithoutTextSendsNothing(t *testing.T) {
	sim := startBarkSim(t, http.StatusOK)
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{sim.server.URL + "/key"}})

	if err := ch.Send("  \n "); err != nil {
		t.Fatalf("an empty message was reported as failed: %v", err)
	}
	if received := sim.received(); len(received) != 0 {
		t.Fatalf("got %d requests for an empty message", len(received))
	}
}

func TestBarkServerThatSaysNothingGivesUp(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })
	ch := newBarkChannelForTest(t, config.BarkConfig{URLs: []string{server.URL + "/key"}})
	if ch.client.Timeout <= 0 {
		t.Fatal("requests have no time limit")
	}
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
