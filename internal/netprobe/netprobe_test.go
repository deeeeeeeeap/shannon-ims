package netprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProberReturnsIPFromCheckURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7\n"))
	}))
	defer srv.Close()

	p := New(Config{Interface: "", URLs: []string{srv.URL}, Timeout: 3 * time.Second})
	ip := p.Probe(context.Background(), FamilyV4)
	if ip != "203.0.113.7" {
		t.Fatalf("Probe = %q, want 203.0.113.7", ip)
	}
}

func TestProberReturnsEmptyOnTimeout(t *testing.T) {
	p := New(Config{Interface: "", URLs: []string{"http://10.255.255.1:1/"}, Timeout: 200 * time.Millisecond})
	if ip := p.Probe(context.Background(), FamilyV4); ip != "" {
		t.Fatalf("Probe = %q, want empty on timeout", ip)
	}
}

func TestExtractIP(t *testing.T) {
	if got := extractIP("2001:db8::abcd"); got != "2001:db8::abcd" {
		t.Fatalf("v6 plain = %q", got)
	}
	if got := extractIP("1.2.3.4"); got != "1.2.3.4" {
		t.Fatalf("v4 plain = %q", got)
	}
	if got := extractIP("not-an-ip"); got != "" {
		t.Fatalf("garbage should yield empty, got %q", got)
	}
}
