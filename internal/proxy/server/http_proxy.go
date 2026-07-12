package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
)

func newHTTPProxyServer(id string, dialer *net.Dialer, stats *TrafficStats, authEnabled bool, username, password string) (*http.Server, error) {
	user := strings.TrimSpace(username)
	pass := strings.TrimSpace(password)
	if authEnabled && (user == "" || pass == "") {
		return nil, fmt.Errorf("代理鉴权已启用但用户名或密码为空")
	}

	h := &httpProxyHandler{
		id:          id,
		dialer:      dialer,
		stats:       stats,
		authEnabled: authEnabled,
		username:    user,
		password:    pass,
	}

	h.transport = &http.Transport{
		Proxy:             nil,
		DialContext:       h.dialContext,
		ForceAttemptHTTP2: false,
	}

	return &http.Server{
		Handler: h,
	}, nil
}

type httpProxyHandler struct {
	id          string
	dialer      *net.Dialer
	stats       *TrafficStats
	transport   *http.Transport
	authEnabled bool
	username    string
	password    string
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.authEnabled && !h.checkProxyAuth(r) {
		h.writeProxyAuthRequired(w)
		return
	}

	if strings.EqualFold(r.Method, http.MethodConnect) {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *httpProxyHandler) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialOutboundConn(ctx, h.dialer, h.stats, network, address)
}

func (h *httpProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL != nil {
		if outReq.URL.Scheme == "" {
			outReq.URL.Scheme = "http"
		}
		if outReq.URL.Host == "" {
			outReq.URL.Host = outReq.Host
		}
	}

	removeHopHeaders(outReq.Header)
	outReq.Header.Del("Proxy-Authorization")

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		h.writeProxyError(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *httpProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := strings.TrimSpace(r.Host)
	if targetAddr == "" {
		h.writeProxyError(w, http.StatusBadRequest, fmt.Errorf("CONNECT 缺少目标地址"))
		return
	}
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	upstream, err := h.dialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		h.writeProxyError(w, http.StatusBadGateway, err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		h.writeProxyError(w, http.StatusInternalServerError, fmt.Errorf("响应不支持 hijack"))
		return
	}

	clientConn, rw, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = clientConn.Close()
			_ = upstream.Close()
		})
	}

	// 双向隧道复制：rw 里可能有已缓冲数据，优先使用它作为上行 reader。
	go func() {
		_, _ = io.Copy(upstream, rw)
		closeBoth()
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstream)
		closeBoth()
	}()
}

func (h *httpProxyHandler) checkProxyAuth(r *http.Request) bool {
	raw := strings.TrimSpace(r.Header.Get("Proxy-Authorization"))
	if raw == "" {
		return false
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return false
	}
	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		return false
	}
	return pair[0] == h.username && pair[1] == h.password
}

func (h *httpProxyHandler) writeProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="vohive-proxy"`)
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = io.WriteString(w, "Proxy Authentication Required\n")
}

func (h *httpProxyHandler) writeProxyError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	if err != nil {
		_, _ = io.WriteString(w, err.Error()+"\n")
		return
	}
	_, _ = io.WriteString(w, http.StatusText(code)+"\n")
}

func removeHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	conn := h.Get("Connection")
	for _, k := range hopByHopHeaders {
		h.Del(k)
	}
	if conn != "" {
		for _, f := range strings.Split(conn, ",") {
			if key := textproto.TrimString(f); key != "" {
				h.Del(key)
			}
		}
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

var _ http.Handler = (*httpProxyHandler)(nil)
