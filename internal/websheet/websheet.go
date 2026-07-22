package websheet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultTTL                      = 10 * time.Minute
	defaultClientTimeout            = 45 * time.Second
	defaultBasePath                 = "/api/websheets"
	defaultMaxResponseBodyBytes     = 4 << 20
	defaultMaxRedirects             = 5
	websheetSessionIDToken          = "{{WEBSHEET_SESSION_ID}}"
	websheetNonceToken              = "{{WEBSHEET_NONCE}}"
	targetQueryParam                = "target_query"
	bootstrapBodyParam              = "bootstrap_body"
)

var (
	ErrDisabled              = errors.New("websheet is disabled")
	ErrNotFound              = errors.New("websheet session not found")
	ErrExpired               = errors.New("websheet session expired")
	ErrInvalidCallback       = errors.New("invalid websheet callback")
	ErrUnsafeURL             = errors.New("websheet URL is not allowed")
	ErrUnauthorized          = errors.New("websheet session unauthorized")
	ErrResponseTooLarge      = errors.New("websheet response is too large")
	ErrTooManyRedirects      = errors.New("websheet redirect limit exceeded")
	ErrUnsafeResponseHeaders = errors.New("websheet response headers are not compatible with safe embedding")
)

//go:embed bridge.js
var websheetBridgeJS string

type Config struct {
	TTL               time.Duration
	BasePath          string
	AllowPrivateHosts bool
	ResolveIP         func(context.Context, string) ([]netip.Addr, error)
	DialContext       func(context.Context, string, string) (net.Conn, error)
	Now               func() time.Time
}

type Broker struct {
	mu                sync.Mutex
	sessions          map[string]*Session
	ttl               time.Duration
	basePath          string
	allowPrivateHosts bool
	resolveIP         func(context.Context, string) ([]netip.Addr, error)
	dialContext       func(context.Context, string, string) (net.Conn, error)
	now               func() time.Time
}

type Request struct {
	URL         string
	UserData    string
	ContentType string
	Title       string
}

type Info struct {
	ID           string `json:"id"`
	EmbedURL     string `json:"embedUrl"`
	MessageNonce string `json:"messageNonce"`
	Title        string `json:"title,omitempty"`
	URL          string `json:"url"`
	Method       string `json:"method"`
}

type Callback struct {
	Source             string `json:"source,omitempty"`
	Controller         string `json:"controller,omitempty"`
	Method             string `json:"method,omitempty"`
	Event              string `json:"event"`
	ResultCode         string `json:"resultCode,omitempty"`
	Href               string `json:"href,omitempty"`
	ActivationCode     string `json:"activationCode,omitempty"`
	DefaultSMDPAddress string `json:"defaultSmdpAddress,omitempty"`
	SMDPFQDN           string `json:"smdpFqdn,omitempty"`
	ICCID              string `json:"iccid,omitempty"`
	IMEI               string `json:"imei,omitempty"`
	NextAction         string `json:"nextAction,omitempty"`
}

const maxCallbackBodyBytes = 16 << 10

func DecodeCallback(r io.Reader) (Callback, error) {
	if r == nil {
		return Callback{}, fmt.Errorf("%w: body is required", ErrInvalidCallback)
	}
	data, err := io.ReadAll(io.LimitReader(r, maxCallbackBodyBytes+1))
	if err != nil {
		return Callback{}, fmt.Errorf("%w: read body", ErrInvalidCallback)
	}
	if len(data) == 0 || len(data) > maxCallbackBodyBytes {
		return Callback{}, fmt.Errorf("%w: body size", ErrInvalidCallback)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var callback Callback
	if err := dec.Decode(&callback); err != nil {
		return Callback{}, fmt.Errorf("%w: decode", ErrInvalidCallback)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Callback{}, fmt.Errorf("%w: trailing data", ErrInvalidCallback)
	}
	if err := validateCallback(&callback); err != nil {
		return Callback{}, err
	}
	return callback, nil
}

func validateCallback(callback *Callback) error {
	if callback == nil {
		return fmt.Errorf("%w: callback is required", ErrInvalidCallback)
	}
	callback.Source = strings.ToLower(strings.TrimSpace(callback.Source))
	if callback.Source != "vowifi" && callback.Source != "odsa" {
		return fmt.Errorf("%w: source", ErrInvalidCallback)
	}
	fields := []struct {
		value    *string
		required bool
		max      int
	}{
		{&callback.Controller, false, 128},
		{&callback.Method, false, 128},
		{&callback.Event, true, 128},
		{&callback.ResultCode, false, 128},
		{&callback.Href, false, 2048},
		{&callback.ActivationCode, false, 2048},
		{&callback.DefaultSMDPAddress, false, 512},
		{&callback.SMDPFQDN, false, 255},
		{&callback.ICCID, false, 64},
		{&callback.IMEI, false, 64},
		{&callback.NextAction, false, 256},
	}
	for _, field := range fields {
		*field.value = strings.TrimSpace(*field.value)
		if field.required && *field.value == "" {
			return fmt.Errorf("%w: required field", ErrInvalidCallback)
		}
		if len(*field.value) > field.max || strings.IndexFunc(*field.value, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: field value", ErrInvalidCallback)
		}
	}
	return nil
}

type Session struct {
	id                string
	messageNonce      string
	target            *url.URL
	userData          string
	contentType       string
	title             string
	expiresAt         time.Time
	basePath          string
	client            *http.Client
	now               func() time.Time
	allowPrivateHosts bool
	resolveIP         func(context.Context, string) ([]netip.Addr, error)

	callbackCh chan Callback
	doneCh     chan struct{}
	doneOnce   sync.Once
}

func New(cfg Config) *Broker {
	ttl := cfg.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	basePath := strings.TrimRight(cfg.BasePath, "/")
	if basePath == "" {
		basePath = defaultBasePath
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	resolveIP := cfg.ResolveIP
	if resolveIP == nil {
		resolveIP = defaultResolveIP
	}
	dialContext := cfg.DialContext
	if dialContext == nil {
		dialer := &net.Dialer{}
		dialContext = dialer.DialContext
	}
	return &Broker{
		sessions:          make(map[string]*Session),
		ttl:               ttl,
		basePath:          basePath,
		allowPrivateHosts: cfg.AllowPrivateHosts,
		resolveIP:         resolveIP,
		dialContext:       dialContext,
		now:               now,
	}
}

func (b *Broker) Create(ctx context.Context, req Request) (*Session, error) {
	if b == nil {
		return nil, errors.New("websheet broker is nil")
	}
	target, err := parseAllowedURL(ctx, req.URL, b.allowPrivateHosts, b.resolveIP)
	if err != nil {
		return nil, err
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	messageNonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	session := &Session{
		id:                id,
		messageNonce:      messageNonce,
		target:            target,
		userData:          strings.TrimSpace(req.UserData),
		contentType:       strings.TrimSpace(req.ContentType),
		title:             strings.TrimSpace(req.Title),
		expiresAt:         b.now().Add(b.ttl),
		basePath:          b.basePath,
		now:               b.now,
		allowPrivateHosts: b.allowPrivateHosts,
		resolveIP:         b.resolveIP,
		callbackCh:        make(chan Callback, 1),
		doneCh:            make(chan struct{}),
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialAllowedContext(b.resolveIP, b.dialContext, b.allowPrivateHosts)
	session.client = &http.Client{
		Transport: transport,
		Timeout:   defaultClientTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.Response != nil {
				if err := validateResponseHeaders(r.Response.Header); err != nil {
					return err
				}
			}
			_, err := parseAllowedURL(r.Context(), r.URL.String(), b.allowPrivateHosts, b.resolveIP)
			if err == nil && len(via) > defaultMaxRedirects {
				return ErrTooManyRedirects
			}
			return err
		},
	}

	b.mu.Lock()
	b.sessions[id] = session
	b.mu.Unlock()
	return session, nil
}

func (b *Broker) Get(id string) (*Session, error) {
	if b == nil {
		return nil, ErrNotFound
	}
	b.mu.Lock()
	session := b.sessions[id]
	if session != nil && session.expired() {
		delete(b.sessions, id)
		session = nil
	}
	b.mu.Unlock()
	if session == nil {
		return nil, ErrNotFound
	}
	return session, nil
}

func (b *Broker) Delete(id string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	delete(b.sessions, id)
	b.mu.Unlock()
}

func (s *Session) Info() Info {
	return Info{
		ID:           s.id,
		EmbedURL:     s.basePath + "/" + url.PathEscape(s.id),
		MessageNonce: s.messageNonce,
		Title:        s.title,
		URL:          s.target.String(),
		Method:       s.method(),
	}
}

func (s *Session) Authorize(r *http.Request) error {
	if s == nil {
		return ErrNotFound
	}
	if s.expired() {
		return ErrExpired
	}
	nonce := ""
	if r != nil {
		nonce = strings.TrimSpace(r.Header.Get("X-Websheet-Nonce"))
	}
	if nonce == "" || s.messageNonce == "" {
		return ErrUnauthorized
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(s.messageNonce)) != 1 {
		return ErrUnauthorized
	}
	return nil
}

func (s *Session) WaitCallback(ctx context.Context) (Callback, error) {
	select {
	case callback := <-s.callbackCh:
		return callback, nil
	case <-s.doneCh:
		return Callback{Event: "finishFlow"}, nil
	case <-ctx.Done():
		return Callback{}, ctx.Err()
	}
}

func (s *Session) WaitDone(ctx context.Context) error {
	select {
	case <-s.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) Done() {
	s.doneOnce.Do(func() {
		close(s.doneCh)
	})
}

func (s *Session) Callback(callback Callback) {
	sendLatest(s.callbackCh, callback)
}

func (s *Session) ServeBootstrap(w http.ResponseWriter, r *http.Request) error {
	if s.expired() {
		return ErrExpired
	}
	target := *s.target
	if s.method() == http.MethodGet && s.userData != "" {
		appendRawQuery(&target, s.userData)
	}
	proxyURL := s.proxyURL(target.String())
	if s.method() == http.MethodGet {
		http.Redirect(w, r, proxyURL, http.StatusFound)
		return nil
	}
	if s.userData != "" {
		proxyURL = appendLocalQuery(proxyURL, bootstrapBodyParam, "1")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := io.WriteString(w, s.postBootstrapHTML(proxyURL))
	return err
}

func (s *Session) Proxy(w http.ResponseWriter, r *http.Request) error {
	if s.expired() {
		return ErrExpired
	}
	rawTarget := strings.TrimSpace(r.URL.Query().Get("target"))
	if rawTarget == "" {
		rawTarget = s.proxyPathTarget(r)
	}
	if rawTarget == "" {
		rawTarget = s.target.String()
	}
	target, err := parseAllowedURL(r.Context(), rawTarget, s.allowPrivateHosts, s.resolveIP)
	if err != nil {
		return err
	}
	if callback, ok := callbackFromURL(target); ok {
		s.Callback(callback)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err := io.WriteString(w, callbackHTML(s.id, s.messageNonce))
		return err
	}

	var body io.Reader
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if r.URL.Query().Get(bootstrapBodyParam) == "1" && s.userData != "" {
			body = strings.NewReader(s.userData)
		} else {
			body = r.Body
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		return fmt.Errorf("create websheet request: %w", err)
	}
	copyProxyHeaders(req.Header, r.Header)
	origin := targetOrigin(target)
	if origin != "" {
		req.Header.Set("Referer", origin+"/")
		if body != nil {
			req.Header.Set("Origin", origin)
		}
	}
	if req.Header.Get("Content-Type") == "" && s.contentType != "" {
		req.Header.Set("Content-Type", s.contentType)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("proxy websheet request: %w", err)
	}
	defer resp.Body.Close()
	if err := validateResponseHeaders(resp.Header); err != nil {
		return err
	}

	data, err := readResponseBody(resp.Body)
	if err != nil {
		return err
	}
	copyResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	contentType := resp.Header.Get("Content-Type")
	if isHTML(contentType) {
		base := target
		if resp.Request != nil && resp.Request.URL != nil {
			base = resp.Request.URL
		}
		html := s.rewriteHTML(string(data), base, shouldInjectBridge(r))
		_, err = io.WriteString(w, html)
		return err
	}
	_, err = w.Write(data)
	return err
}

func (s *Session) method() string {
	if s.contentType != "" {
		return http.MethodPost
	}
	return http.MethodGet
}

func (s *Session) expired() bool {
	return !s.now().Before(s.expiresAt)
}

func (s *Session) proxyURL(rawTarget string) string {
	if target, err := url.Parse(rawTarget); err == nil && target.Scheme != "" && target.Host != "" {
		values := url.Values{}
		if target.RawQuery != "" {
			values.Set(targetQueryParam, target.RawQuery)
		}
		proxyPath := s.basePath + "/" + url.PathEscape(s.id) + "/proxy/" + target.Scheme + "/" + target.Host + target.EscapedPath()
		if target.EscapedPath() == "" {
			proxyPath += "/"
		}
		if encoded := values.Encode(); encoded != "" {
			proxyPath += "?" + encoded
		}
		return proxyPath
	}
	values := url.Values{}
	values.Set("target", rawTarget)
	return s.basePath + "/" + url.PathEscape(s.id) + "/proxy?" + values.Encode()
}

func (s *Session) proxyPathTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	prefix := s.basePath + "/" + url.PathEscape(s.id) + "/proxy/"
	escapedPath := r.URL.EscapedPath()
	if !strings.HasPrefix(escapedPath, prefix) {
		return ""
	}
	rest := strings.TrimPrefix(escapedPath, prefix)
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return ""
	}
	target := url.URL{
		Scheme: parts[0],
		Host:   parts[1],
	}
	if len(parts) == 3 {
		pathValue, err := url.PathUnescape("/" + parts[2])
		if err != nil {
			return ""
		}
		target.Path = pathValue
	} else {
		target.Path = "/"
	}
	target.RawQuery = r.URL.Query().Get(targetQueryParam)
	return target.String()
}

func (s *Session) postBootstrapHTML(action string) string {
	values, err := url.ParseQuery(strings.TrimLeft(s.userData, "?&"))
	var body bytes.Buffer
	body.WriteString("<!doctype html><html><body>")
	body.WriteString(`<form id="websheet" method="post" action="`)
	body.WriteString(html.EscapeString(action))
	body.WriteString(`">`)
	if err == nil {
		for key, items := range values {
			for _, item := range items {
				body.WriteString(`<input type="hidden" name="`)
				body.WriteString(html.EscapeString(key))
				body.WriteString(`" value="`)
				body.WriteString(html.EscapeString(item))
				body.WriteString(`">`)
			}
		}
	} else if s.userData != "" {
		body.WriteString(`<input type="hidden" name="payload" value="`)
		body.WriteString(html.EscapeString(s.userData))
		body.WriteString(`">`)
	}
	body.WriteString(`</form><script>document.getElementById("websheet").submit();</script></body></html>`)
	return body.String()
}

func (s *Session) rewriteHTML(doc string, base *url.URL, injectBridge bool) string {
	docBase := s.documentBaseURL(doc, base)
	rewritten := attrURLPattern.ReplaceAllStringFunc(doc, func(match string) string {
		parts := attrURLPattern.FindStringSubmatch(match)
		if len(parts) < 6 {
			return match
		}
		attr := parts[1]
		raw := parts[3]
		if raw == "" {
			raw = parts[4]
		}
		if raw == "" {
			raw = parts[5]
		}
		next, ok := s.rewriteURL(raw, docBase)
		if !ok {
			return match
		}
		return attr + `="` + html.EscapeString(next) + `"`
	})
	if !injectBridge {
		return rewritten
	}
	script := s.bridgeScript(docBase)
	lower := strings.ToLower(rewritten)
	if idx := strings.Index(lower, "<head"); idx >= 0 {
		if end := strings.Index(rewritten[idx:], ">"); end >= 0 {
			insertAt := idx + end + 1
			return rewritten[:insertAt] + script + rewritten[insertAt:]
		}
	}
	if idx := strings.LastIndex(lower, "</head>"); idx >= 0 {
		return rewritten[:idx] + script + rewritten[idx:]
	}
	if idx := strings.LastIndex(lower, "</body>"); idx >= 0 {
		return rewritten[:idx] + script + rewritten[idx:]
	}
	return script + rewritten
}

func shouldInjectBridge(r *http.Request) bool {
	if r == nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest"))) {
	case "", "document", "iframe", "frame":
		return true
	default:
		return false
	}
}

func (s *Session) documentBaseURL(doc string, fallback *url.URL) *url.URL {
	match := baseHrefPattern.FindStringSubmatch(doc)
	if len(match) < 5 {
		return fallback
	}
	raw := match[2]
	if raw == "" {
		raw = match[3]
	}
	if raw == "" {
		raw = match[4]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return fallback
	}
	return fallback.ResolveReference(ref)
}

func (s *Session) rewriteURL(raw string, base *url.URL) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return raw, false
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "javascript:") || strings.HasPrefix(lower, "mailto:") || strings.HasPrefix(lower, "tel:") || strings.HasPrefix(lower, "data:") {
		return raw, false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw, false
	}
	target := base.ResolveReference(ref)
	return s.proxyURL(target.String()), true
}

func (s *Session) bridgeScript(carrierBase *url.URL) string {
	script := strings.ReplaceAll(websheetBridgeJS, websheetSessionIDToken, jsString(s.id))
	script = strings.ReplaceAll(script, websheetNonceToken, jsString(s.messageNonce))
	script = strings.ReplaceAll(script, "{{ABSOLUTE_PATH_PROXY_PREFIX}}", jsString(s.absolutePathProxyPrefix(carrierBase)))
	return "<script>\n" + script + "\n</script>"
}

func (s *Session) absolutePathProxyPrefix(carrierBase *url.URL) string {
	origin := targetOrigin(carrierBase)
	if origin == "" {
		return ""
	}
	return strings.TrimRight(s.proxyURL(origin+"/"), "/")
}
var (
	attrURLPattern  = regexp.MustCompile("(?i)\\b(href|src|action)=(\"([^\"]*)\"|'([^']*)'|([^\\s\"'=<>`]+))")
	baseHrefPattern = regexp.MustCompile("(?is)<base\\b[^>]*\\bhref=(\"([^\"]*)\"|'([^']*)'|([^\\s\"'=<>`]+))[^>]*>")
)

func appendLocalQuery(raw string, key string, value string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	values := parsed.Query()
	values.Set(key, value)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func copyProxyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "authorization", "cookie", "host", "referer", "origin", "content-length", "accept-encoding",
			"connection", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func targetOrigin(target *url.URL) string {
	if target == nil || target.Scheme == "" || target.Host == "" {
		return ""
	}
	return target.Scheme + "://" + target.Host
}

func copyResponseHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "content-length":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isHTML(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return strings.Contains(strings.ToLower(contentType), "html")
	}
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

func validateResponseHeaders(headers http.Header) error {
	for _, name := range []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"X-Content-Security-Policy",
		"X-Frame-Options",
		"Set-Cookie",
		"Set-Cookie2",
	} {
		if len(headers.Values(name)) != 0 {
			return ErrUnsafeResponseHeaders
		}
	}
	return nil
}

func readResponseBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, defaultMaxResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read websheet response: %w", err)
	}
	if len(data) > defaultMaxResponseBodyBytes {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

func defaultResolveIP(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		ip, ok := netip.AddrFromSlice(addr.IP)
		if ok {
			ips = append(ips, ip.Unmap())
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("host resolved without an IP address")
	}
	return ips, nil
}

func resolveHostIPs(
	ctx context.Context,
	host string,
	resolveIP func(context.Context, string) ([]netip.Addr, error),
) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if resolveIP == nil {
		resolveIP = defaultResolveIP
	}
	ips, err := resolveIP(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("host resolved without an IP address")
	}
	return ips, nil
}

func dialAllowedContext(
	resolveIP func(context.Context, string) ([]netip.Addr, error),
	dialContext func(context.Context, string, string) (net.Conn, error),
	allowPrivate bool,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse websheet dial address: %w", err)
		}
		if !allowPrivate && isLocalHostname(host) {
			return nil, fmt.Errorf("%w: local dial host", ErrUnsafeURL)
		}
		ips, err := resolveHostIPs(ctx, host, resolveIP)
		if err != nil {
			return nil, fmt.Errorf("resolve websheet dial host: %w", err)
		}
		for _, ip := range ips {
			if !ip.IsValid() || (!allowPrivate && unsafeIP(ip.Unmap())) {
				return nil, fmt.Errorf("%w: unsafe dial address", ErrUnsafeURL)
			}
		}
		var lastErr error
		for _, ip := range ips {
			conn, err := dialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("dial websheet target: %w", lastErr)
	}
}

func parseAllowedURL(
	ctx context.Context,
	raw string,
	allowPrivate bool,
	resolveIP func(context.Context, string) ([]netip.Addr, error),
) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: URL is required", ErrUnsafeURL)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse websheet URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrUnsafeURL, parsed.Scheme)
	}
	if !allowPrivate && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q", ErrUnsafeURL, parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: host is required", ErrUnsafeURL)
	}
	if allowPrivate {
		return parsed, nil
	}
	if isLocalHostname(host) {
		return nil, fmt.Errorf("%w: local host %q", ErrUnsafeURL, host)
	}
	ips, err := resolveHostIPs(ctx, host, resolveIP)
	if err != nil {
		return nil, fmt.Errorf("resolve websheet host: %w", err)
	}
	for _, ip := range ips {
		if !ip.IsValid() || unsafeIP(ip.Unmap()) {
			return nil, fmt.Errorf("%w: private address %q", ErrUnsafeURL, host)
		}
	}
	return parsed, nil
}

func isLocalHostname(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

var sharedAddressPrefix = netip.MustParsePrefix("100.64.0.0/10")

func unsafeIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsGlobalUnicast() ||
		sharedAddressPrefix.Contains(ip) ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified()
}

func appendRawQuery(target *url.URL, raw string) {
	raw = strings.TrimLeft(raw, "?&")
	if raw == "" {
		return
	}
	if target.RawQuery == "" {
		target.RawQuery = raw
		return
	}
	target.RawQuery += "&" + raw
}

func callbackFromURL(target *url.URL) (Callback, bool) {
	if !strings.Contains(target.Path, "/_callback") {
		return Callback{}, false
	}
	query := target.Query()
	event := firstValue(query, "event", "callback", "action", "method")
	if event == "" {
		parts := strings.Split(strings.Trim(target.Path, "/"), "/")
		if len(parts) > 0 {
			event = parts[len(parts)-1]
		}
	}
	if normalize(event) == "callback" || normalize(event) == "esim" || event == "" {
		event = callbackEventFromQuery(query)
	}
	return Callback{
		Event:              event,
		ActivationCode:     firstValue(query, "activationCode", "activation_code"),
		DefaultSMDPAddress: firstValue(query, "defaultSmdpAddress", "default_smdp_address"),
		SMDPFQDN:           firstValue(query, "smdpFqdn", "smdp", "defaultSmdpAddress"),
		ICCID:              firstValue(query, "iccid", "ICCID"),
		IMEI:               firstValue(query, "imei", "IMEI"),
		NextAction:         firstValue(query, "nextAction", "next_action"),
	}, true
}

func callbackEventFromQuery(values url.Values) string {
	switch {
	case firstValue(values, "activationCode", "activation_code") != "":
		return "profileReadyWithActivationCode"
	case firstValue(values, "defaultSmdpAddress", "smdp", "smdpFqdn") != "":
		return "profileReadyWithDefaultSmdp"
	case firstValue(values, "nextAction", "next_action") != "":
		return "finishFlow"
	default:
		return "finishFlow"
	}
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func firstValue(values url.Values, keys ...string) string {
	for _, key := range keys {
		if value := values.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func callbackHTML(sessionID, nonce string) string {
	return "<!doctype html><html><body><script>try{const o=new URL(window.location.href).origin;window.parent.postMessage({type:\"vohive-websheet-callback\",sessionId:"+jsString(sessionID)+",nonce:"+jsString(nonce)+",callback:{source:\"odsa\",event:\"finishFlow\"}},o)}catch(_){}</script>Carrier flow returned to VoHive.</body></html>"
}

func jsString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	return `"` + value + `"`
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate websheet id: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func randomNonce() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate websheet nonce: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func sendLatest[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
		select {
		case <-ch:
		default:
		}
		ch <- value
	}
}
