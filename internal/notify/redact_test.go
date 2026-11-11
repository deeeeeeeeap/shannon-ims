package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTelegramFailedPollsDoNotPrintTheBotToken(t *testing.T) {
	server := startTelegramSim(t)
	ch := newTelegramChannelForTest(t, server)

	printed := &lockedBuffer{}
	telegramLibraryReports.out.SetOutput(printed)
	t.Cleanup(func() { telegramLibraryReports.out.SetOutput(os.Stderr) })

	server.Close()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = ch.Start()
	}()
	waitUntil(t, 10*time.Second, func() bool { return strings.Contains(printed.String(), "Failed to get updates") })
	_ = ch.Close()
	select {
	case <-stopped:
	case <-time.After(15 * time.Second):
		t.Fatal("the listener did not stop")
	}

	out := printed.String()
	checkAbsent(t, "what the library printed", out, telegramSimSecret)
	if !strings.Contains(out, redactedTelegramToken+"/getUpdates") {
		t.Fatalf("what the library printed does not name the request that failed:\n%s", out)
	}
}

func TestTelegramLibraryReportsLeaveOutTheBotToken(t *testing.T) {
	var printed bytes.Buffer
	reports := telegramLibraryLog{out: log.New(&printed, "", 0)}

	reports.Println(&url.Error{Op: "Post", URL: "https://api.telegram.org/bot" + telegramSimToken + "/getUpdates", Err: io.EOF})
	reports.Println("Failed to get updates, retrying in 3 seconds...")
	reports.Printf("Endpoint: %s, params: %v\n", "https://proxy.example.com/bot"+telegramSimToken+"/sendMessage", nil)

	want := "Post \"https://api.telegram.org/bot[redacted]/getUpdates\": EOF\n" +
		"Failed to get updates, retrying in 3 seconds...\n" +
		"Endpoint: https://proxy.example.com/bot[redacted]/sendMessage, params: <nil>\n"
	if printed.String() != want {
		t.Fatalf("printed %q, want %q", printed.String(), want)
	}
}

func TestLoggableURLKeepsSchemeAndHostOnly(t *testing.T) {
	for given, want := range map[string]string{
		"https://api.day.app/" + urlPathSecret:                            "https://api.day.app/[redacted]",
		"https://api.day.app/" + urlPathSecret + "/title/body?level=1":    "https://api.day.app/[redacted]",
		"https://hooks.example.com:8443/?key=" + urlQuerySecret:           "https://hooks.example.com:8443/[redacted]",
		"https://hooks.example.com/#" + urlPathSecret:                     "https://hooks.example.com/[redacted]",
		"http://" + proxyUser + ":" + proxySecret + "@" + "10.0.0.2:7890": "http://10.0.0.2:7890",
		"  http://127.0.0.1:7890/  ":                                      "http://127.0.0.1:7890",
		"socks5://[::1]:1080":                                             "socks5://[::1]:1080",
		"api.day.app/" + urlPathSecret:                                    "[url]",
		"http://bad host/" + urlPathSecret:                                "[url]",
		"":                                                                "[url]",
	} {
		if got := loggableURL(given); got != want {
			t.Errorf("loggableURL(%q) = %q, want %q", given, got, want)
		}
	}
}

func TestLoggableErrorKeepsTheCauseAndDropsTheURL(t *testing.T) {
	if loggableError(nil) != nil {
		t.Fatal("no error became an error")
	}

	plain := errors.New("HTTP status 500")
	if got := loggableError(plain); got != plain {
		t.Fatalf("an error without a URL was changed: %v", got)
	}

	direct := &url.Error{Op: "Post", URL: "https://api.day.app/" + urlPathSecret, Err: context.DeadlineExceeded}
	got := loggableError(direct)
	checkAbsent(t, "the error", got.Error(), urlPathSecret)
	if !errors.Is(got, context.DeadlineExceeded) || !isTimeout(got) {
		t.Fatalf("the cause was lost: %v", got)
	}
	if want := `Post "https://api.day.app/[redacted]": context deadline exceeded`; got.Error() != want {
		t.Fatalf("error = %q, want %q", got.Error(), want)
	}

	wrapped := fmt.Errorf("创建 HTTP 请求失败: %w", &url.Error{Op: "parse", URL: "http://bad host/" + urlPathSecret, Err: errors.New("invalid character")})
	checkAbsent(t, "the error", loggableError(wrapped).Error(), urlPathSecret)

	telegram := &url.Error{Op: "Post", URL: "https://api.telegram.org/bot" + telegramSimToken + "/sendMessage", Err: io.EOF}
	checkAbsent(t, "the error", loggableError(telegram).Error(), telegramSimSecret)
	text := errors.New("request to https://api.telegram.org/bot" + telegramSimToken + "/getMe failed")
	if got, want := loggableError(text).Error(), "request to https://api.telegram.org/bot[redacted]/getMe failed"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}
