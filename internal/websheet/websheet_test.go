package websheet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
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
		"https://100.64.0.1/",
		"https://255.255.255.255/",
		"file:///etc/passwd",
	} {
		if _, err := b.Create(context.Background(), Request{URL: raw}); !errors.Is(err, ErrUnsafeURL) {
			t.Fatalf("Create(%q) err=%v, want ErrUnsafeURL", raw, err)
		}
	}
}

func TestCreateAllowsPublicHTTPS(t *testing.T) {
	b := New(Config{})
	s, err := b.Create(context.Background(), Request{URL: "https://203.0.113.10/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if info.EmbedURL == "" || info.Method != "GET" {
		t.Fatalf("info=%+v", info)
	}
}

func TestInfoUsesOpaqueHandleAndSeparateMessageNonce(t *testing.T) {
	b := New(Config{})
	s, err := b.Create(context.Background(), Request{URL: "https://203.0.113.10/"})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if strings.Contains(info.EmbedURL, "?") || strings.Contains(info.EmbedURL, "token") {
		t.Fatalf("EmbedURL contains a query credential: %q", info.EmbedURL)
	}
	if info.MessageNonce == "" || strings.Contains(info.EmbedURL, info.MessageNonce) {
		t.Fatalf("message nonce was empty or present in URL: %+v", info)
	}

	validReq := httptest.NewRequest(http.MethodPost, "/api/websheets/"+info.ID+"/callback", nil)
	validReq.Header.Set("X-Websheet-Nonce", info.MessageNonce)
	if err := s.Authorize(validReq); err != nil {
		t.Fatalf("Authorize(valid nonce) error=%v", err)
	}
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/api/websheets/"+info.ID+"/callback", nil),
		httptest.NewRequest(http.MethodPost, "/api/websheets/"+info.ID+"/callback?token="+url.QueryEscape(info.MessageNonce), nil),
	} {
		if err := s.Authorize(req); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("Authorize(without nonce header) error=%v, want ErrUnauthorized", err)
		}
	}
}

func TestDecodeCallbackRejectsControlCharacters(t *testing.T) {
	_, err := DecodeCallback(strings.NewReader(`{"source":"vowifi","event":"dismiss\u007fFlow"}`))
	if !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("DecodeCallback() error=%v, want ErrInvalidCallback", err)
	}
}

func TestPostBootstrapProxiesRawUserDataBody(t *testing.T) {
	const rawPostData = "method%3Dupdate-tc-loc%26devicetype%3Dphone%26authtoken%3Dsynthetic"
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

func TestProxyRejectsOversizedResponseBeforeWritingBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, strings.Repeat("x", (4<<20)+1))
	}))
	defer upstream.Close()

	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: upstream.URL + "/large"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, s.proxyURL(upstream.URL+"/large"), nil)
	rec := httptest.NewRecorder()
	err = s.Proxy(rec, req)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("Proxy() error=%v, want ErrResponseTooLarge", err)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("Proxy() wrote %d response bytes before rejecting oversized body", rec.Body.Len())
	}
}

func TestProxyRejectsExcessiveRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Count(r.URL.Path, "/next") < 6 {
			http.Redirect(w, r, r.URL.Path+"/next", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer upstream.Close()

	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: upstream.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, s.proxyURL(upstream.URL+"/start"), nil)
	rec := httptest.NewRecorder()
	if err := s.Proxy(rec, req); !errors.Is(err, ErrTooManyRedirects) {
		t.Fatalf("Proxy() error=%v, want ErrTooManyRedirects", err)
	}
}

func TestProxyRejectsRedirectToPrivateTarget(t *testing.T) {
	resolveIP := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	b := New(Config{ResolveIP: resolveIP})
	s, err := b.Create(context.Background(), Request{URL: "https://carrier.invalid/start"})
	if err != nil {
		t.Fatal(err)
	}

	redirect := httptest.NewRequest(http.MethodGet, "https://127.0.0.1/private", nil)
	original := httptest.NewRequest(http.MethodGet, "https://carrier.invalid/start", nil)
	err = s.client.CheckRedirect(redirect, []*http.Request{original})
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("redirect policy error=%v, want ErrUnsafeURL", err)
	}
}

func TestProxyRejectsDNSChangeBeforeActualDial(t *testing.T) {
	var resolveCalls atomic.Int32
	var dialCalled atomic.Bool
	resolveIP := func(context.Context, string) ([]netip.Addr, error) {
		if resolveCalls.Add(1) <= 2 {
			return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	dialContext := func(context.Context, string, string) (net.Conn, error) {
		dialCalled.Store(true)
		return nil, errors.New("unexpected synthetic dial")
	}

	b := New(Config{
		ResolveIP:   resolveIP,
		DialContext: dialContext,
	})
	s, err := b.Create(context.Background(), Request{URL: "https://carrier.invalid/start"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, s.proxyURL("https://carrier.invalid/start"), nil)
	rec := httptest.NewRecorder()
	err = s.Proxy(rec, req)
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("Proxy() error=%v, want ErrUnsafeURL after DNS change", err)
	}
	if dialCalled.Load() {
		t.Fatal("Proxy() called the dialer with an unsafe resolved address")
	}
}

func TestDialAllowedContextConnectsOnlyToValidatedIP(t *testing.T) {
	resolveIP := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "carrier.invalid" {
			t.Fatalf("resolver host=%q want carrier.invalid", host)
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	var dialAddress string
	var peer net.Conn
	dialContext := func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialAddress = address
		client, server := net.Pipe()
		peer = server
		return client, nil
	}

	dial := dialAllowedContext(resolveIP, dialContext, false)
	conn, err := dial(context.Background(), "tcp", "carrier.invalid:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	defer peer.Close()

	if dialAddress != "203.0.113.10:443" {
		t.Fatalf("dial address=%q want validated IP address", dialAddress)
	}
}

func TestProxyFailsClosedOnUpstreamSetCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "synthetic_session=synthetic; Secure; HttpOnly")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer upstream.Close()

	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: upstream.URL + "/cookie"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, s.proxyURL(upstream.URL+"/cookie"), nil)
	rec := httptest.NewRecorder()
	err = s.Proxy(rec, req)
	if err == nil {
		t.Fatal("Proxy() silently removed Set-Cookie instead of failing closed")
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("Proxy() wrote %d response bytes before rejecting Set-Cookie", rec.Body.Len())
	}
}

func TestProxyFailsClosedOnRedirectSetCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Add("Set-Cookie", "synthetic_redirect=synthetic; HttpOnly")
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer upstream.Close()

	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: upstream.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, s.proxyURL(upstream.URL+"/start"), nil)
	rec := httptest.NewRecorder()
	err = s.Proxy(rec, req)
	if !errors.Is(err, ErrUnsafeResponseHeaders) {
		t.Fatalf("Proxy() error=%v, want ErrUnsafeResponseHeaders", err)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("Proxy() wrote %d response bytes after redirect Set-Cookie", rec.Body.Len())
	}
}

func TestProxyFailsClosedOnEmbeddingSecurityHeaders(t *testing.T) {
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options"} {
		t.Run(header, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(header, "synthetic-policy")
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "unexpected")
			}))
			defer upstream.Close()

			b := New(Config{AllowPrivateHosts: true})
			s, err := b.Create(context.Background(), Request{URL: upstream.URL + "/protected"})
			if err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(http.MethodGet, s.proxyURL(upstream.URL+"/protected"), nil)
			rec := httptest.NewRecorder()
			err = s.Proxy(rec, req)
			if !errors.Is(err, ErrUnsafeResponseHeaders) {
				t.Fatalf("Proxy() error=%v, want ErrUnsafeResponseHeaders", err)
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("Proxy() wrote %d response bytes before rejecting %s", rec.Body.Len(), header)
			}
		})
	}
}

func TestRewriteHTMLKeepsProxyURLsRelativeAndCredentialFree(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	rewritten := s.rewriteHTML(
		`<html><head><base href="/softphone/"><script src="main-es2015.js"></script></head></html>`,
		base,
		true,
	)
	if strings.Contains(rewritten, "http://127.0.0.1:7575") || strings.Contains(rewritten, "?token=") {
		t.Fatalf("rewritten html leaked an origin or query credential: %s", rewritten)
	}
	if !strings.Contains(rewritten, `/api/websheets/`) || !strings.Contains(rewritten, `/proxy/https/attdashboard.wireless.att.com/softphone/main-es2015.js`) {
		t.Fatalf("rewritten html missing relative proxy URL: %s", rewritten)
	}
}

func TestBridgePathPrefixUsesOpaqueSessionPath(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	script := s.bridgeScript(base)
	prefix := extractJSStringConst(t, script, "absolutePathProxyPrefix")
	if strings.Contains(prefix, "?") || strings.Contains(prefix, s.Info().MessageNonce) {
		t.Fatalf("appendable path prefix includes a credential: %s", prefix)
	}
}

func TestBridgeDoesNotExposeCredentialsOrBroadcast(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	script := s.bridgeScript(base)
	for _, forbidden := range []string{
		"websheetToken",
		"?token=",
		"BroadcastChannel",
		"localStorage",
		`postMessage(message, "*")`,
		"callbackURL",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("bridge script contains forbidden credential channel %q", forbidden)
		}
	}
	for _, required := range []string{"websheetNonce", "websheetSessionID", "postMessage(message, shellOrigin)"} {
		if !strings.Contains(script, required) {
			t.Fatalf("bridge script missing %q", required)
		}
	}
}

func TestBridgeDetectsATTAddressValidationOnlyForMutationResponses(t *testing.T) {
	b := New(Config{AllowPrivateHosts: true})
	s, err := b.Create(context.Background(), Request{URL: "https://attdashboard.wireless.att.com/softphone/primary/reseller/r017"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := url.Parse("https://attdashboard.wireless.att.com/softphone/primary/reseller/r017")
	if err != nil {
		t.Fatal(err)
	}

	script := s.bridgeScript(base)
	for _, marker := range []string{
		"inspectATTAddressResponse",
		"e911AddressValidated",
		`status === "validated"`,
		`method === "GET"`,
		"window.parent.postMessage",
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
	s, err := b.Create(context.Background(), Request{URL: "https://203.0.113.10/"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := b.Get(s.Info().ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get expired err=%v, want ErrNotFound", err)
	}
}
