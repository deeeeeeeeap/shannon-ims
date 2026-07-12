package upstreamproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	socks5Version          = 0x05
	socks5AuthNone         = 0x00
	socks5AuthUserPassword = 0x02
	socks5AuthNoAcceptable = 0xFF
	socks5UserPassVersion  = 0x01
	socks5CmdUDPAssociate  = 0x03
	socks5AtypIPv4         = 0x01
	socks5AtypDomain       = 0x03
	socks5AtypIPv6         = 0x04
	socks5ReplySuccess     = 0x00
)

const (
	ProbeStageTCPConnect   = "tcp_connect"
	ProbeStageHandshake    = "socks5_handshake"
	ProbeStageUDPAssociate = "udp_associate"
	ProbeStageOK           = "ok"
)

type ProbeConfig struct {
	ProxyAddr string
	Username  string
	Password  string
	Timeout   time.Duration
}

type ProbeResult struct {
	ProxyAddr      string `json:"proxy_addr"`
	Stage          string `json:"stage"`
	Reachable      bool   `json:"reachable"`
	HandshakeOK    bool   `json:"handshake_ok"`
	UDPAssociateOK bool   `json:"udp_associate_ok"`
	AuthMethod     string `json:"auth_method,omitempty"`
	RelayAddr      string `json:"relay_addr,omitempty"`
	DurationMS     int64  `json:"duration_ms"`
	Diagnosis      string `json:"diagnosis,omitempty"`
	Hint           string `json:"hint,omitempty"`
	Error          string `json:"error,omitempty"`
}

func (r ProbeResult) OK() bool {
	return r.Reachable && r.HandshakeOK && r.UDPAssociateOK
}

func (r ProbeResult) FailureSummary() string {
	if r.OK() {
		return "前置代理探测通过"
	}

	parts := make([]string, 0, 3)
	if strings.TrimSpace(r.Diagnosis) != "" {
		parts = append(parts, r.Diagnosis)
	}
	if strings.TrimSpace(r.Hint) != "" {
		parts = append(parts, "建议: "+r.Hint)
	}
	if strings.TrimSpace(r.Error) != "" {
		parts = append(parts, "细节: "+r.Error)
	}
	return strings.Join(parts, "；")
}

func ProbeSOCKS5(ctx context.Context, cfg ProbeConfig) (ProbeResult, error) {
	startedAt := time.Now()
	result := ProbeResult{
		ProxyAddr: strings.TrimSpace(cfg.ProxyAddr),
		Stage:     ProbeStageTCPConnect,
	}
	if result.ProxyAddr == "" {
		result.Error = "empty proxy addr"
		return finalizeProbeResult(result, startedAt), errors.New(result.Error)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", result.ProxyAddr)
	if err != nil {
		result.Error = fmt.Sprintf("代理 TCP 连接失败: %v", err)
		return finalizeProbeResult(result, startedAt), err
	}
	defer conn.Close()

	result.Reachable = true
	if err := conn.SetDeadline(probeDeadline(ctx, timeout)); err != nil {
		result.Error = fmt.Sprintf("设置探测超时失败: %v", err)
		return finalizeProbeResult(result, startedAt), err
	}

	selectedMethod, err := probeHandshake(conn, cfg.Username, cfg.Password)
	if err != nil {
		result.Stage = ProbeStageHandshake
		result.Error = err.Error()
		return finalizeProbeResult(result, startedAt), err
	}
	result.Stage = ProbeStageUDPAssociate
	result.HandshakeOK = true
	result.AuthMethod = socks5AuthMethodName(selectedMethod)

	relayAddr, err := probeUDPAssociate(conn)
	if err != nil {
		result.Error = err.Error()
		return finalizeProbeResult(result, startedAt), err
	}

	result.Stage = ProbeStageOK
	result.UDPAssociateOK = true
	result.RelayAddr = relayAddr.String()
	return finalizeProbeResult(result, startedAt), nil
}

func finalizeProbeResult(result ProbeResult, startedAt time.Time) ProbeResult {
	result.DurationMS = time.Since(startedAt).Milliseconds()
	annotateProbeResult(&result)
	return result
}

func annotateProbeResult(result *ProbeResult) {
	if result == nil {
		return
	}
	if result.OK() {
		result.Diagnosis = "代理支持标准 SOCKS5 UDP Associate"
		return
	}

	errText := strings.ToLower(strings.TrimSpace(result.Error))
	switch result.Stage {
	case ProbeStageTCPConnect:
		result.Diagnosis = "无法与代理建立 TCP 连接"
		switch {
		case strings.Contains(errText, "connection refused"):
			result.Hint = "代理地址可达，但目标端口没有监听 SOCKS5 服务"
		case strings.Contains(errText, "i/o timeout"):
			result.Hint = "检查代理地址、端口、防火墙或 ACL，确认当前主机可以访问该端口"
		default:
			result.Hint = "检查代理地址、端口和网络连通性"
		}
	case ProbeStageHandshake:
		switch {
		case strings.Contains(errText, "0xff"):
			result.Diagnosis = "代理拒绝了当前提供的认证方式"
			result.Hint = "检查代理是否要求用户名密码，或当前凭据是否与服务端配置一致"
		case strings.Contains(errText, "用户名密码鉴权但未提供凭据"):
			result.Diagnosis = "代理要求用户名密码认证"
			result.Hint = "为该前置代理填写正确的用户名和密码"
		case strings.Contains(errText, "鉴权失败"):
			result.Diagnosis = "代理用户名或密码错误"
			result.Hint = "检查保存的用户名密码是否正确"
		case strings.Contains(errText, "版本不匹配"):
			result.Diagnosis = "目标端口不是标准 SOCKS5 服务"
			result.Hint = "确认这里填写的是 SOCKS5 端口，而不是 HTTP、混合端口或其他协议端口"
		case strings.Contains(errText, "响应读取失败: eof"):
			result.Diagnosis = "代理在 SOCKS5 握手阶段直接断开了连接"
			result.Hint = "通常表示该端口并非标准 SOCKS5，或服务端策略直接拒绝当前来源连接"
		default:
			result.Diagnosis = "SOCKS5 握手失败"
			result.Hint = "检查代理协议类型、认证方式和服务端访问策略"
		}
	case ProbeStageUDPAssociate:
		switch {
		case strings.Contains(errText, "被拒绝: 状态码"):
			result.Diagnosis = "代理明确拒绝了 UDP Associate"
			result.Hint = "通常表示代理未开启 UDP 转发，或当前策略禁止 UDP relay"
		case strings.Contains(errText, "响应解析失败: 读取响应头失败: eof"):
			result.Diagnosis = "代理在 UDP Associate 阶段直接断开了连接"
			result.Hint = "通常表示该 SOCKS5 只支持 TCP，不支持 UDP Associate，或 UDP relay 未开启"
		case strings.Contains(errText, "版本不匹配"):
			result.Diagnosis = "代理返回了非标准的 UDP Associate 响应"
			result.Hint = "确认目标端口是标准 SOCKS5 UDP Associate 端口，而不是其他混合协议端口"
		default:
			result.Diagnosis = "UDP Associate 失败"
			result.Hint = "检查代理是否支持 SOCKS5 UDP Associate，以及是否允许当前来源使用 UDP relay"
		}
	default:
		result.Diagnosis = "前置代理探测失败"
		result.Hint = "请检查代理协议、认证和 UDP 转发能力"
	}
}

func probeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func probeHandshake(conn io.ReadWriter, username, password string) (byte, error) {
	methods := []byte{socks5AuthNone}
	if strings.TrimSpace(username) != "" {
		methods = []byte{socks5AuthUserPassword, socks5AuthNone}
	}

	req := make([]byte, 2+len(methods))
	req[0] = socks5Version
	req[1] = byte(len(methods))
	copy(req[2:], methods)
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("socks5 握手发送失败: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return 0, fmt.Errorf("socks5 握手响应读取失败: %w", err)
	}
	if resp[0] != socks5Version {
		return 0, fmt.Errorf("socks5 版本不匹配: 期望 0x05, 实际 0x%02x", resp[0])
	}

	selectedMethod := resp[1]
	switch selectedMethod {
	case socks5AuthNone:
		return selectedMethod, nil
	case socks5AuthUserPassword:
		if strings.TrimSpace(username) == "" {
			return 0, errors.New("socks5 服务器要求用户名密码鉴权但未提供凭据")
		}
		if err := probeUserPasswordAuth(conn, username, password); err != nil {
			return 0, err
		}
		return selectedMethod, nil
	case socks5AuthNoAcceptable:
		return 0, errors.New("socks5 服务器拒绝了所有鉴权方法 (0xFF)")
	default:
		return 0, fmt.Errorf("socks5 服务器选择了不支持的鉴权方法: 0x%02x", selectedMethod)
	}
}

func probeUserPasswordAuth(conn io.ReadWriter, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("socks5 用户名或密码过长 (>255 字节)")
	}

	req := make([]byte, 1+1+len(username)+1+len(password))
	req[0] = socks5UserPassVersion
	req[1] = byte(len(username))
	copy(req[2:2+len(username)], username)
	req[2+len(username)] = byte(len(password))
	copy(req[3+len(username):], password)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 鉴权请求发送失败: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 鉴权响应读取失败: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 鉴权失败: 状态码 0x%02x", resp[1])
	}
	return nil
}

func probeUDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	req := buildProbeUDPAssociateRequest(probeUDPAssociateClientIP(conn))
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 请求发送失败: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应解析失败: 读取响应头失败: %w", err)
	}
	if header[0] != socks5Version {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应版本不匹配: 0x%02x", header[0])
	}
	if header[1] != socks5ReplySuccess {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 被拒绝: 状态码 0x%02x", header[1])
	}

	ip, err := readProbeReplyIP(conn, header[3])
	if err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应解析失败: %w", err)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("socks5 UDP ASSOCIATE 响应解析失败: 读取端口失败: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

func probeUDPAssociateClientIP(conn net.Conn) net.IP {
	if conn != nil {
		if tcpRemote, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcpRemote.IP != nil && tcpRemote.IP.To4() == nil {
			return net.IPv6zero
		}
	}
	return net.IPv4zero
}

func buildProbeUDPAssociateRequest(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return []byte{
			socks5Version,
			socks5CmdUDPAssociate,
			0x00,
			socks5AtypIPv4,
			v4[0], v4[1], v4[2], v4[3],
			0x00, 0x00,
		}
	}

	v6 := ip.To16()
	if v6 == nil {
		v6 = net.IPv6zero
	}
	req := make([]byte, 4+16+2)
	req[0] = socks5Version
	req[1] = socks5CmdUDPAssociate
	req[3] = socks5AtypIPv6
	copy(req[4:20], v6)
	return req
}

func readProbeReplyIP(r io.Reader, atyp byte) (net.IP, error) {
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("读取 IPv4 地址失败: %w", err)
		}
		return net.IP(buf), nil
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("读取 IPv6 地址失败: %w", err)
		}
		return net.IP(buf), nil
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, fmt.Errorf("读取域名长度失败: %w", err)
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("读取域名失败: %w", err)
		}
		return net.IP(buf), nil
	default:
		return nil, fmt.Errorf("未知地址类型: 0x%02x", atyp)
	}
}

func socks5AuthMethodName(method byte) string {
	switch method {
	case socks5AuthNone:
		return "noauth"
	case socks5AuthUserPassword:
		return "username_password"
	default:
		return fmt.Sprintf("0x%02x", method)
	}
}
