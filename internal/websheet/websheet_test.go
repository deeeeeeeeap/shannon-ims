package websheet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCreateRejectsPrivateAndNonHTTPSURLs(t *testing.T) {
	b := New(Config{})
	for _, raw := range []string{
		"http://example.com/",
		"https://127.0.0.1/",
		"https://10.0.0.1/",
		"https://192.168.1.1/",
		"file:///etc/passwd",
	} {
		if _, err := b.Create(context.Background(), Request{URL: raw}); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("Create(%q) err=%v, want ErrUnsafeURL", raw, err)
		}
	}
}

func TestCreateAllowsPublicHTTPS(t *testing.T) {
	b := New(Config{})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.EmbedURL == "" || info.Method != "GET" {
		t.Fatalf("info=%+v", info)
	}
}

func TestInfoEmbedURLCarriesSessionAccessToken(t *testing.T) {
	b := New(Config{})
	s, err := b.Create(context.Background(), Request{URL: "https://203.0.113.10/"})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if !strings.Contains(info.EmbedURL, "token=") {
		t.Fatalf("EmbedURL=%q, want session token query", info.EmbedURL)
	}

	validReq := httptest.NewRequest(http.MethodGet, info.EmbedURL, nil)
	if err := s.Authorize(validReq); err != nil {
		t.Fatalf("Authorize(valid token) error=%v", err)
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/api/websheets/"+info.ID, nil)
	if err := s.Authorize(missingReq); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authorize(missing token) error=%v, want ErrUnauthorized", err)
	}
}

func TestPostBootstrapProxiesRawUserDataBody(t *testing.T) {
	const rawPostData = "method%3Dupdate-tc-loc%26devicetype%3Dphone%26authtoken%3DAXBCRgUM"
	var gotBody string
	var gotContentType string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><body>ok</body></html>")
	}))
	defer upstream.Close()

	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{
		URL:         upstream.URL + "/softphone/primary/reseller/r017",
		UserData:    rawPostData,
		ContentType: "application/x-www-form-urlencoded",
	})
	if err != nil {
		t.Fatal(err)
	}

	bootstrapReq := httptest.NewRequest(http.MethodGet, s.Info().EmbedURL, nil)
	bootstrapRec := httptest.NewRecorder()
	if err := s.ServeBootstrap(bootstrapRec, bootstrapReq); err != nil {
		t.Fatal(err)
	}
	action := extractFormAction(t, bootstrapRec.Body.String())

	proxyReq := httptest.NewRequest(http.MethodPost, action, nil)
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proxyRec := httptest.NewRecorder()
	if err := s.Proxy(proxyRec, proxyReq); err != nil {
		t.Fatal(err)
	}
	if gotBody != rawPostData {
		t.Fatalf("proxied body=%q want raw %q", gotBody, rawPostData)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type=%q want application/x-www-form-urlencoded", gotContentType)
	}
}

func TestRewriteHTMLKeepsProxyURLsRelativeToBrowserOrigin(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(strings.SplitN(s.Info().EmbedURL, "token=", 2)[1], "")
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	rewritten := s.rewriteHTML(
		`<html><head><base href="/softphone/"><script src="main-es2015.js"></script></head></html>`,
		base,
		token,
		true,
	)
	if strings.Contains(rewritten, "http://127.0.0.1:7575") {
		t.Fatalf("rewritten html leaked backend origin: %s", rewritten)
	}
	if !strings.Contains(rewritten, `/api/websheets/`) || !strings.Contains(rewritten, `/proxy/https/attdashboard.wireless.att.com/softphone/main-es2015.js`) {
		t.Fatalf("rewritten html missing relative proxy URL: %s", rewritten)
	}
}

func TestBridgePathPrefixKeepsTokenOutOfAppendablePath(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.SplitN(s.Info().EmbedURL, "token=", 2)[1]
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	script := s.bridgeScript(token, base)
	prefix := extractJSStringConst(t, script, "absolutePathProxyPrefix")
	if strings.Contains(prefix, "?token=") {
		t.Fatalf("appendable path prefix includes token query: %s", prefix)
	}
	if !strings.Contains(script, `const websheetToken = "`) {
		t.Fatalf("bridge script missing separate websheet token: %s", script)
	}
}

func TestBridgeDetectsATTAddressValidationOnlyForMutationResponses(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	token := strings.SplitN(s.Info().EmbedURL, "token=", 2)[1]
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	script := s.bridgeScript(token, base)
	for _, marker := range []string{
		"inspectATTAddressResponse",
		"e911AddressValidated",
		`status === "validated"`,
		`method === "GET"`,
		"window.top.postMessage",
		"BroadcastChannel",
		"localStorage.setItem",
		"vohive-websheet-complete",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("bridge script missing %q: %s", marker, script)
		}
	}
}

func extractJSStringConst(t *testing.T, script string, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`const\s+` + regexp.QuoteMeta(name) + `\s*=\s*"([^"]*)"`)
	match := pattern.FindStringSubmatch(script)
	if len(match) != 2 {
		t.Fatalf("script missing const %s: %s", name, script)
	}
	return match[1]
}

func extractFormAction(t *testing.T, html string) string {
	t.Helper()
	match := regexp.MustCompile(`action="([^"]+)"`).FindStringSubmatch(html)
	if len(match) != 2 {
		t.Fatalf("bootstrap html missing form action: %s", html)
	}
	return match[1]
}

func TestSessionExpires(t *testing.T) {
	now := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	b := New(Config{
		TTL: time.Minute,
		Now: func() time.Time { return now },
	})
	s, err := b.Create(context.Background(), Request{URL: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := b.Get(s.Info().ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get expired err=%v, want ErrNotFound", err)
	}
}
