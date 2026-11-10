package upstreamproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
)

const (
	ProbeStageTCPConnect   = "tcp_connect"
	ProbeStageHandshake    = "socks5_handshake"
	ProbeStageUDPAssociate = "udp_associate"
	ProbeStageOK           = "ok"
)

const defaultProbeTimeout = 5 * time.Second

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
	// RelayAddr is the UDP relay address a tunnel will actually send to.
	RelayAddr string `json:"relay_addr,omitempty"`
	// RelayAdvertised is the relay address as the proxy announced it, set
	// only when it differs from RelayAddr.
	RelayAdvertised string `json:"relay_advertised,omitempty"`
	// RelayAdjustment says how the announced address was interpreted
	// (a transport.Socks5RelayAdjustment); empty when it was used as is.
	RelayAdjustment string `json:"relay_adjustment,omitempty"`
	// CredentialsIgnored reports that the proxy has no username/password
	// support, so the saved credentials are not used.
	CredentialsIgnored bool `json:"credentials_ignored,omitempty"`
	// Warnings are conditions that do not fail the probe but can keep a
	// tunnel from working, or that the operator should know about.
	Warnings []string `json:"warnings,omitempty"`
	// Attempts is how many probes ProbeSOCKS5WithRetry made; a single
	// ProbeSOCKS5 leaves it unset.
	Attempts int `json:"attempts,omitempty"`

	DurationMS int64  `json:"duration_ms"`
	Diagnosis  string `json:"diagnosis,omitempty"`
	Hint       string `json:"hint,omitempty"`
	Error      string `json:"error,omitempty"`
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

// ProbeSOCKS5 checks that a proxy can carry a tunnel: TCP reachability,
// method negotiation and authentication, and UDP ASSOCIATE.
//
// It runs the protocol code the tunnel's transport runs, with the same
// negotiation order and the same relay address handling, so a proxy that
// passes here is later used exactly the way it was probed.
func ProbeSOCKS5(ctx context.Context, cfg ProbeConfig) (ProbeResult, error) {
	probe := probeRun{
		startedAt:    time.Now(),
		credentialed: cfg.Username != "" || cfg.Password != "",
	}
	result := ProbeResult{
		ProxyAddr: strings.TrimSpace(cfg.ProxyAddr),
		Stage:     ProbeStageTCPConnect,
	}
	if result.ProxyAddr == "" {
		result.Error = "empty proxy addr"
		return probe.finish(result, nil), errors.New(result.Error)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	// Each step is limited to timeout by the client; the whole probe keeps
	// the bound it always had, one timeout to connect and one for the rest.
	ctx, cancel := context.WithTimeout(ctx, 2*timeout)
	defer cancel()

	conn, err := transport.DialSocks5(ctx, result.ProxyAddr, transport.Socks5Options{
		Username: cfg.Username,
		Password: cfg.Password,
		Timeout:  timeout,
	})
	if err != nil {
		var se *transport.Socks5Error
		if errors.As(err, &se) && se.Stage == transport.Socks5StageConnect {
			result.Error = fmt.Sprintf("代理 TCP 连接失败: %v", se.Err)
			return probe.fail(result, err)
		}
		result.Reachable = true
		result.Stage = ProbeStageHandshake
		result.Error = probeHandshakeErrorText(err)
		return probe.fail(result, err)
	}
	defer conn.Close()

	result.Reachable = true
	result.HandshakeOK = true
	result.Stage = ProbeStageUDPAssociate
	result.AuthMethod = socks5AuthMethodName(conn.AuthMethod())
	result.CredentialsIgnored = conn.CredentialsIgnored()

	relay, err := conn.UDPAssociate(ctx)
	if err != nil {
		result.Error = probeAssociateErrorText(err)
		return probe.fail(result, err)
	}

	result.Stage = ProbeStageOK
	result.UDPAssociateOK = true
	result.RelayAddr = relay.Addr.String()
	result.RelayAdjustment = string(relay.Adjustment)
	if advertised := relay.Advertised.String(); advertised != result.RelayAddr {
		result.RelayAdvertised = advertised
	}
	return probe.finish(result, nil), nil
}

// probeRun is the context a result is explained in.
type probeRun struct {
	startedAt time.Time
	// credentialed: a username was configured, so username/password was
	// offered to the proxy.
	credentialed bool
}

func (p probeRun) finish(result ProbeResult, err error) ProbeResult {
	result.DurationMS = time.Since(p.startedAt).Milliseconds()
	annotateProbeResult(&result, err, p.credentialed)
	return result
}

// fail completes a failed result and returns it with its error.
func (p probeRun) fail(result ProbeResult, cause error) (ProbeResult, error) {
	result = p.finish(result, cause)
	return result, &probeError{text: result.Error, cause: cause}
}

// probeError words a failure the way the result does, which is what the
// operator is shown, and keeps the typed cause for errors.Is and errors.As.
type probeError struct {
	text  string
	cause error
}

func (e *probeError) Error() string { return e.text }
func (e *probeError) Unwrap() error { return e.cause }

// probeFailure is what the diagnosis needs to know about an error.
type probeFailure struct {
	reason     transport.Socks5Reason
	peerClosed bool
	timeout    bool
	refused    bool
	unresolved bool
}

func classifyProbeFailure(err error) probeFailure {
	var f probeFailure
	if err == nil {
		return f
	}
	var se *transport.Socks5Error
	if errors.As(err, &se) {
		f.reason = se.Reason
		f.peerClosed = se.PeerClosed()
	}
	var netErr net.Error
	f.timeout = (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded)
	f.refused = errors.Is(err, syscall.ECONNREFUSED)
	var dnsErr *net.DNSError
	f.unresolved = errors.As(err, &dnsErr)
	return f
}

// annotateProbeResult turns the outcome into an explanation and a next step
// for the operator. It works from the typed failure, never from message text.
func annotateProbeResult(result *ProbeResult, err error, credentialed bool) {
	if result == nil {
		return
	}
	if result.OK() {
		result.Diagnosis = "代理支持标准 SOCKS5 UDP Associate"
		result.Warnings = probeWarnings(*result)
		return
	}

	f := classifyProbeFailure(err)
	switch result.Stage {
	case ProbeStageTCPConnect:
		result.Diagnosis = "无法与代理建立 TCP 连接"
		switch {
		case f.refused:
			result.Hint = "代理地址可达，但目标端口没有监听 SOCKS5 服务"
		case f.unresolved:
			result.Hint = "代理主机名无法解析，检查域名拼写和本机 DNS"
		case f.timeout:
			result.Hint = "检查代理地址、端口、防火墙或 ACL，确认当前主机可以访问该端口"
		default:
			result.Hint = "检查代理地址、端口和网络连通性"
		}
	case ProbeStageHandshake:
		switch {
		case f.reason == transport.Socks5ReasonCredentialsRequired,
			// Without credentials only "no authentication" was offered, so a
			// refusal means the proxy insists on authenticating.
			f.reason == transport.Socks5ReasonNoAcceptableMethod && !credentialed:
			result.Diagnosis = "代理要求用户名密码认证"
			result.Hint = "为该前置代理填写正确的用户名和密码"
		case f.reason == transport.Socks5ReasonNoAcceptableMethod:
			result.Diagnosis = "代理拒绝了当前提供的认证方式"
			result.Hint = "代理既不接受用户名密码认证也不接受免认证接入，确认其认证方式（例如只允许指定来源地址）是否适用于本机"
		case f.reason == transport.Socks5ReasonAuthRejected:
			result.Diagnosis = "代理用户名或密码错误"
			result.Hint = "检查保存的用户名密码是否正确"
		case f.reason == transport.Socks5ReasonInvalidCredentials:
			result.Diagnosis = "用户名或密码超过 SOCKS5 允许的 255 字节"
			result.Hint = "缩短该前置代理的用户名或密码"
		case f.reason == transport.Socks5ReasonNotSocks5:
			result.Diagnosis = "目标端口不是标准 SOCKS5 服务"
			result.Hint = "确认这里填写的是 SOCKS5 端口，而不是 HTTP、混合端口或其他协议端口"
		case f.peerClosed:
			result.Diagnosis = "代理在 SOCKS5 握手阶段直接断开了连接"
			result.Hint = "通常表示该端口并非标准 SOCKS5，或服务端策略直接拒绝当前来源连接"
		case f.timeout:
			result.Diagnosis = "代理在 SOCKS5 握手阶段没有响应"
			result.Hint = "端口可以连接但没有应答，通常表示该端口不是 SOCKS5 服务，或代理过载、被中间设备拦截"
		default:
			result.Diagnosis = "SOCKS5 握手失败"
			result.Hint = "检查代理协议类型、认证方式和服务端访问策略"
		}
	case ProbeStageUDPAssociate:
		switch {
		case f.reason == transport.Socks5ReasonRequestRejected:
			result.Diagnosis = "代理明确拒绝了 UDP Associate"
			result.Hint = "通常表示代理未开启 UDP 转发，或当前策略禁止 UDP relay"
		case f.reason == transport.Socks5ReasonNotSocks5:
			result.Diagnosis = "代理返回了非标准的 UDP Associate 响应"
			result.Hint = "确认目标端口是标准 SOCKS5 UDP Associate 端口，而不是其他混合协议端口"
		case f.reason == transport.Socks5ReasonMalformedReply:
			result.Diagnosis = "代理返回的 UDP 中继地址不可用"
			result.Hint = "代理通告的中继地址或端口无效，检查代理的 UDP 监听地址和对外地址配置"
		case f.peerClosed:
			result.Diagnosis = "代理在 UDP Associate 阶段直接断开了连接"
			result.Hint = "通常表示该 SOCKS5 只支持 TCP，不支持 UDP Associate，或 UDP relay 未开启"
		case f.timeout:
			result.Diagnosis = "代理在 UDP Associate 阶段没有响应"
			result.Hint = "通常表示该 SOCKS5 只支持 TCP，不支持 UDP Associate，或 UDP relay 未开启"
		default:
			result.Diagnosis = "UDP Associate 失败"
			result.Hint = "检查代理是否支持 SOCKS5 UDP Associate，以及是否允许当前来源使用 UDP relay"
		}
	default:
		result.Diagnosis = "前置代理探测失败"
		result.Hint = "请检查代理协议、认证和 UDP 转发能力"
	}
}

func probeWarnings(result ProbeResult) []string {
	var warnings []string
	if result.CredentialsIgnored {
		warnings = append(warnings, "代理不支持用户名密码认证，已保存的凭据未被使用，当前为免认证接入")
	}
	switch transport.Socks5RelayAdjustment(result.RelayAdjustment) {
	case transport.Socks5RelayPrivate:
		warnings = append(warnings, "代理通告的 UDP 中继地址是内网地址；本机若不能直达该内网，隧道的 UDP 数据将无法通过")
	case transport.Socks5RelayDomainUnresolved:
		warnings = append(warnings, "代理通告的 UDP 中继域名无法解析，已改用代理自身地址")
	}
	return warnings
}

// probeIOErrorText describes a failed exchange. A connection closed by the
// proxy is said in words; the other causes keep the system's own wording.
func probeIOErrorText(prefix string, err error) string {
	var se *transport.Socks5Error
	if errors.As(err, &se) && se.Err != nil {
		err = se.Err
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return prefix + ": 代理关闭了连接"
	}
	return fmt.Sprintf("%s: %v", prefix, err)
}

func probeHandshakeErrorText(err error) string {
	var se *transport.Socks5Error
	if !errors.As(err, &se) {
		return fmt.Sprintf("socks5 握手失败: %v", err)
	}
	switch se.Reason {
	case transport.Socks5ReasonNotSocks5:
		return fmt.Sprintf("socks5 版本不匹配: 期望 0x05, 实际 0x%02x", se.Code)
	case transport.Socks5ReasonNoAcceptableMethod:
		return "socks5 服务器拒绝了所有鉴权方法 (0xFF)"
	case transport.Socks5ReasonCredentialsRequired:
		return "socks5 服务器要求用户名密码鉴权但未提供凭据"
	case transport.Socks5ReasonUnsupportedMethod:
		return fmt.Sprintf("socks5 服务器选择了不支持的鉴权方法: 0x%02x", se.Code)
	case transport.Socks5ReasonAuthRejected:
		return fmt.Sprintf("socks5 鉴权失败: 状态码 0x%02x", se.Code)
	case transport.Socks5ReasonInvalidCredentials:
		return "socks5 用户名或密码过长 (>255 字节)"
	}
	switch se.Op {
	case "send method offer":
		return probeIOErrorText("socks5 握手发送失败", err)
	case "read method selection":
		return probeIOErrorText("socks5 握手响应读取失败", err)
	case "send credentials":
		return probeIOErrorText("socks5 鉴权请求发送失败", err)
	case "read authentication status":
		return probeIOErrorText("socks5 鉴权响应读取失败", err)
	}
	return probeIOErrorText("socks5 握手失败", err)
}

func probeAssociateErrorText(err error) string {
	var se *transport.Socks5Error
	if !errors.As(err, &se) {
		return fmt.Sprintf("socks5 UDP ASSOCIATE 失败: %v", err)
	}
	switch se.Reason {
	case transport.Socks5ReasonNotSocks5:
		return fmt.Sprintf("socks5 UDP ASSOCIATE 响应版本不匹配: 0x%02x", se.Code)
	case transport.Socks5ReasonRequestRejected:
		return fmt.Sprintf("socks5 UDP ASSOCIATE 被拒绝: 状态码 0x%02x (%s)", se.Code, socks5ReplyMeaning(se.Code))
	case transport.Socks5ReasonMalformedReply:
		return probeIOErrorText("socks5 UDP ASSOCIATE 响应解析失败", err)
	}
	return probeIOErrorText("socks5 UDP ASSOCIATE 未收到完整响应", err)
}

func socks5ReplyMeaning(code byte) string {
	switch code {
	case 0x01:
		return "代理内部错误"
	case 0x02:
		return "规则不允许"
	case 0x03:
		return "网络不可达"
	case 0x04:
		return "主机不可达"
	case 0x05:
		return "连接被拒绝"
	case 0x06:
		return "TTL 超时"
	case 0x07:
		return "不支持该命令"
	case 0x08:
		return "不支持该地址类型"
	default:
		return "未定义的状态码"
	}
}

func socks5AuthMethodName(method byte) string {
	switch method {
	case transport.Socks5AuthNone:
		return "noauth"
	case transport.Socks5AuthUserPassword:
		return "username_password"
	default:
		return fmt.Sprintf("0x%02x", method)
	}
}
