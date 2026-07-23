package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSSEStreamHeartbeatOutlivesHTTPWriteTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/stream", func(c *gin.Context) {
		stream, err := newSSEStream(c, 20*time.Millisecond)
		if err != nil {
			c.Status(http.StatusInternalServerError)
			return
		}
		if err := stream.Event("ready", map[string]string{"status": "ready"}); err != nil {
			return
		}

		heartbeat := time.NewTicker(10 * time.Millisecond)
		defer heartbeat.Stop()
		finish := time.NewTimer(90 * time.Millisecond)
		defer finish.Stop()
		for {
			select {
			case <-heartbeat.C:
				if err := stream.Heartbeat(); err != nil {
					return
				}
			case <-finish.C:
				_ = stream.Event("done", map[string]string{"status": "done"})
				return
			}
		}
	})

	testServer := httptest.NewUnstartedServer(router)
	testServer.Config.WriteTimeout = 30 * time.Millisecond
	testServer.Start()
	defer testServer.Close()

	client := testServer.Client()
	client.Timeout = 2 * time.Second
	response, err := client.Get(testServer.URL + "/stream")
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want %d; body=%s", response.StatusCode, http.StatusOK, body)
	}
	if !strings.Contains(string(body), "event:done") {
		t.Fatalf("stream ended before done event: %q", body)
	}
	if !strings.Contains(string(body), ": heartbeat") {
		t.Fatalf("stream contained no heartbeat: %q", body)
	}
}
