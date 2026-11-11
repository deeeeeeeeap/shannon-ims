package notify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/pkg/logger"
)

// What stands for the credentials that the URLs of the channels carry. None
// of them is one the masking of the logger would recognise by its form.
var (
	urlPathSecret  = "Kq7ZpX2mW9vB4nR8sT1uYc"
	urlQuerySecret = "n3Wt-Jx8LmQ2-pRz5Vy"
	proxyUser      = "proxy-account"
	proxySecret    = "Hd4-sW8kPq-Zt1"
	// The part of a Telegram bot token after the number of the bot.
	telegramSimSecret = strings.Repeat("AbC_dEf-", 4) + "xYz"
	telegramSimToken  = "123456789:" + telegramSimSecret
)

// unreachableURL returns the URL of a port on this machine that nothing
// listens on.
func unreachableURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen on the loopback interface: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return "http://" + address
}

// recordLog starts the product logger and returns a function that gives what
// has been logged since, as the log file gets it: after the masking of the
// logger. The function waits until an entry with the message until has come.
func recordLog(t *testing.T) func(until string) string {
	t.Helper()
	logger.Setup(logger.LogConfig{Debug: true, Filename: filepath.Join(t.TempDir(), "app.log")})
	entries := logger.GlobalBroadcaster.Subscribe()
	t.Cleanup(func() { logger.GlobalBroadcaster.Unsubscribe(entries) })

	var logged strings.Builder
	return func(until string) string {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case entry := <-entries:
				fmt.Fprintf(&logged, "%s %s %s\n", entry.Level, entry.Message, entry.Fields)
				if entry.Message == until {
					return logged.String()
				}
			case <-deadline:
				t.Fatalf("no log entry %q; logged so far:\n%s", until, logged.String())
			}
		}
	}
}

// logOfFailedBroadcast sends one notification through a manager whose only
// channel is ch and returns what was logged until the manager had logged that
// the channel failed.
func logOfFailedBroadcast(t *testing.T, ch Channel) string {
	t.Helper()
	logged := recordLog(t)
	newTestNotifyManager(ch).broadcastWithContext(NotificationContext{Event: "notification", Text: "hello"})
	return logged("通知渠道发送失败")
}

// checkAbsent reports every one of the secrets that text shows. The test goes
// on, so that one run tells all the places a secret shows up in.
func checkAbsent(t *testing.T, what, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			t.Errorf("%s shows %q:\n%s", what, secret, text)
		}
	}
}

// startTelegramSim stands in for the Telegram bot API as far as a bot needs
// it to start and to send.
func startTelegramSim(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			_, _ = io.WriteString(w, `{"ok":true,"result":{"id":42,"is_bot":true,"first_name":"sim","username":"sim_bot"}}`)
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			_, _ = io.WriteString(w, `{"ok":true,"result":{"message_id":1,"date":1,"chat":{"id":1,"type":"private"}}}`)
		default:
			_, _ = io.WriteString(w, `{"ok":true,"result":[]}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newTelegramChannelForTest(t *testing.T, server *httptest.Server) *TelegramChannel {
	t.Helper()
	ch, err := NewTelegramChannel(config.TelegramConfig{Enabled: true, BotToken: telegramSimToken, ChatID: 1, BaseURL: server.URL})
	if err != nil || ch == nil {
		t.Fatalf("cannot make the channel: %v", err)
	}
	return ch
}

// lockedBuffer is a buffer that is written and read from different goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// isTimeout tells whether err is the error of a wait that ran out of time.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
