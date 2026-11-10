package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Severity classifies a configuration finding.
type Severity string

const (
	// SeverityError marks a value the process cannot run with; startup stops.
	SeverityError Severity = "error"
	// SeverityWarning marks a value that is ignored or replaced by a documented
	// fallback. Startup continues so an existing deployment is never bricked by
	// a newly introduced check, but the operator is told what was wrong.
	SeverityWarning Severity = "warning"
)

// Issue is one configuration finding. Message never echoes credential values.
type Issue struct {
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Message  string   `json:"message"`
}

func (i Issue) String() string {
	return fmt.Sprintf("[%s] %s: %s", i.Severity, i.Path, i.Message)
}

// HasErrors reports whether any issue blocks startup.
func HasErrors(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == SeverityError {
			return true
		}
	}
	return false
}

// SerialSettings is the effective serial line configuration of an AT port.
type SerialSettings struct {
	BaudRate int
	DataBits int
	StopBits int
	Parity   string // "N", "O" or "E"
}

// SerialSettings resolves the serial parameters of a device entry. Unset or
// unsupported values fall back to 115200 8N1, which is what USB CDC modems use;
// Validate reports the unsupported ones.
func (d DeviceConfig) SerialSettings() SerialSettings {
	s := SerialSettings{
		BaudRate: DefaultSerialBaudRate,
		DataBits: DefaultSerialDataBits,
		StopBits: DefaultSerialStopBits,
		Parity:   DefaultSerialParity,
	}
	if d.BaudRate > 0 {
		s.BaudRate = d.BaudRate
	}
	if d.DataBits >= 5 && d.DataBits <= 8 {
		s.DataBits = d.DataBits
	}
	if d.StopBits == 1 || d.StopBits == 2 {
		s.StopBits = d.StopBits
	}
	switch p := strings.ToUpper(strings.TrimSpace(d.Parity)); p {
	case "N", "O", "E":
		s.Parity = p
	}
	return s
}

type validator struct {
	issues []Issue
}

func (v *validator) errorf(path, format string, args ...any) {
	v.issues = append(v.issues, Issue{Severity: SeverityError, Path: path, Message: fmt.Sprintf(format, args...)})
}

func (v *validator) warnf(path, format string, args ...any) {
	v.issues = append(v.issues, Issue{Severity: SeverityWarning, Path: path, Message: fmt.Sprintf(format, args...)})
}

// Validate inspects a loaded configuration and returns every finding in
// document order. It never mutates cfg.
func Validate(cfg *Config) []Issue {
	if cfg == nil {
		return nil
	}
	v := &validator{}
	v.server(cfg.Server)
	v.devices(cfg.Devices)
	v.proxy(cfg.Proxy, cfg.Devices)
	v.notifications(cfg)
	v.voiceGateway(cfg.VoWiFi)
	return v.issues
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

// splitListenAddress accepts "host:port" and ":port".
func splitListenAddress(addr string) (host string, port int, err error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("端口不是数字")
	}
	return host, port, nil
}

func (v *validator) server(s ServerConfig) {
	if strings.TrimSpace(s.Port) == "" {
		return // Load always fills the default; an empty value only occurs in hand-built configs.
	}
	_, port, err := splitListenAddress(s.Port)
	if err != nil {
		v.errorf("server.port", "监听地址无效，应为 端口 或 主机:端口")
		return
	}
	// 0 asks the kernel for a free port; useful for tests, harmless otherwise.
	if port != 0 && !validPort(port) {
		v.errorf("server.port", "端口 %d 超出范围 1-65535", port)
	}
}

func (v *validator) devices(devices []DeviceConfig) {
	seenID := make(map[string]int, len(devices))
	seenIMEI := make(map[string]int, len(devices))
	for i, d := range devices {
		path := fmt.Sprintf("devices[%d]", i)
		id := strings.TrimSpace(d.ID)
		if id == "" {
			v.warnf(path+".id", "设备缺少 id，该条目无法被管理")
		} else if first, dup := seenID[id]; dup {
			v.warnf(path+".id", "设备 id %q 与 devices[%d] 重复，后者不会被启动", id, first)
		} else {
			seenID[id] = i
		}

		if imei := strings.TrimSpace(d.ModemIMEI); imei != "" {
			key := NormalizeIMEI(imei)
			if key == "" {
				v.warnf(path+".modem_imei", "IMEI 格式无效（至少需要 14 位数字），无法用于匹配模组")
			} else if first, dup := seenIMEI[key]; dup {
				v.warnf(path+".modem_imei", "IMEI 与 devices[%d] 重复，两个条目会争抢同一模组", first)
			} else {
				seenIMEI[key] = i
			}
		}

		if err := ValidateDeviceBackend(d.DeviceBackend); err != nil {
			v.warnf(path+".device_backend", "%v；当前会按 at 处理", err)
		}
		if err := ValidateMBIMTransport(d.MBIMTransport); err != nil {
			v.warnf(path+".mbim_transport", "%v；当前会按 auto 处理", err)
		}
		if strings.TrimSpace(d.ESIMTransport) != "" {
			if err := ValidateESIMTransport(d.ESIMTransport); err != nil {
				v.warnf(path+".esim_transport", "不支持的取值，可选值: at, qmi, mbim；当前会按 at 处理")
			}
		}
		if d.ProxyPort != 0 && !validPort(d.ProxyPort) {
			v.warnf(path+".proxy_port", "端口 %d 超出范围 1-65535", d.ProxyPort)
		}

		v.deviceSerial(path, d)
		v.deviceOperatorSelection(path, d)

		if d.ESIMSwitch.ReinitWindowMS < 0 {
			v.warnf(path+".esim_switch.reinit_window_ms", "不能为负数")
		}
		if d.ESIMSwitch.NASAttachTimeoutMS < 0 {
			v.warnf(path+".esim_switch.nas_attach_timeout_ms", "不能为负数")
		}
		if d.ESIMSwitch.ReinitWindowMS > 0 && !d.ESIMSwitch.EventGatedConverge {
			v.warnf(path+".esim_switch.reinit_window_ms", "仅在 event_gated_converge=true 时生效，当前会被忽略")
		}
	}
}

func (v *validator) deviceSerial(path string, d DeviceConfig) {
	if d.BaudRate < 0 {
		v.warnf(path+".baud_rate", "波特率不能为负数；当前会使用 %d", DefaultSerialBaudRate)
	}
	if d.DataBits != 0 && (d.DataBits < 5 || d.DataBits > 8) {
		v.warnf(path+".data_bits", "数据位应为 5-8；当前会使用 %d", DefaultSerialDataBits)
	}
	if d.StopBits != 0 && d.StopBits != 1 && d.StopBits != 2 {
		v.warnf(path+".stop_bits", "停止位应为 1 或 2；当前会使用 %d", DefaultSerialStopBits)
	}
	switch strings.ToUpper(strings.TrimSpace(d.Parity)) {
	case "", "N", "O", "E":
	default:
		v.warnf(path+".parity", "校验位应为 N、O 或 E；当前会使用 %s", DefaultSerialParity)
	}
}

func isPLMN(s string) bool {
	if len(s) != 5 && len(s) != 6 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (v *validator) deviceOperatorSelection(path string, d DeviceConfig) {
	mode := strings.ToLower(strings.TrimSpace(d.OperatorSelectionMode))
	plmn := strings.TrimSpace(d.OperatorSelectionPLMN)
	switch mode {
	case "", OperatorSelectionAutomatic:
	case OperatorSelectionManual:
		if plmn == "" {
			v.warnf(path+".operator_selection_plmn", "手动选网缺少 PLMN，当前会按自动选网处理")
		}
	default:
		v.warnf(path+".operator_selection_mode", "不支持的取值 %q，可选值: automatic, manual；当前会按自动选网处理", mode)
	}
	if plmn != "" && !isPLMN(plmn) {
		v.warnf(path+".operator_selection_plmn", "PLMN 应为 5 或 6 位数字")
	}
}

func (v *validator) proxy(p ProxyConfig, devices []DeviceConfig) {
	deviceIDs := make(map[string]struct{}, len(devices))
	for _, d := range devices {
		if id := strings.TrimSpace(d.ID); id != "" {
			deviceIDs[id] = struct{}{}
		}
	}
	seenID := make(map[string]int, len(p.Instances))
	type listener struct {
		index int
		host  string
	}
	listeners := make(map[int][]listener)

	for i, inst := range p.Instances {
		path := fmt.Sprintf("proxy.instances[%d]", i)
		id := strings.TrimSpace(inst.ID)
		if id == "" {
			v.warnf(path+".id", "代理实例缺少 id")
		} else if first, dup := seenID[id]; dup {
			v.warnf(path+".id", "代理实例 id %q 与 proxy.instances[%d] 重复", id, first)
		} else {
			seenID[id] = i
		}

		switch strings.ToLower(strings.TrimSpace(inst.Mode)) {
		case "", "socks5", "http":
		default:
			v.warnf(path+".mode", "不支持的代理模式 %q，可选值: socks5, http", inst.Mode)
		}
		if !inst.Enabled {
			continue
		}

		if !validPort(inst.ListenPort) {
			v.warnf(path+".listen_port", "端口 %d 超出范围 1-65535，该实例无法监听", inst.ListenPort)
		} else {
			host := strings.TrimSpace(inst.ListenAddr)
			for _, other := range listeners[inst.ListenPort] {
				if listenHostsOverlap(host, other.host) {
					v.warnf(path+".listen_port", "与 proxy.instances[%d] 监听同一地址和端口 %d，后启动的实例会失败", other.index, inst.ListenPort)
					break
				}
			}
			listeners[inst.ListenPort] = append(listeners[inst.ListenPort], listener{index: i, host: host})
		}
		if host := strings.TrimSpace(inst.ListenAddr); host != "" && net.ParseIP(host) == nil {
			v.warnf(path+".listen_addr", "监听地址不是合法的 IP")
		}
		if inst.AuthEnabled && (strings.TrimSpace(inst.Username) == "" || inst.Password == "") {
			v.warnf(path+".auth_enabled", "已开启认证但用户名或密码为空")
		}
		if dev := strings.TrimSpace(inst.DeviceID); dev != "" {
			if _, ok := deviceIDs[dev]; !ok {
				v.warnf(path+".device_id", "绑定的设备 %q 不在 devices 列表中", dev)
			}
		}
	}
}

// listenHostsOverlap reports whether two listen hosts collide on one port.
// An empty or unspecified host binds every address.
func listenHostsOverlap(a, b string) bool {
	wildcard := func(h string) bool {
		if h == "" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsUnspecified()
	}
	return wildcard(a) || wildcard(b) || strings.EqualFold(a, b)
}

func validHTTPURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (v *validator) notifications(cfg *Config) {
	if t := cfg.Telegram; t.Enabled {
		if strings.TrimSpace(t.BotToken) == "" || t.ChatID == 0 {
			v.warnf("telegram", "已启用但缺少 bot_token 或 chat_id，通知不会发送")
		}
		if p := strings.TrimSpace(t.Proxy); p != "" {
			if u, err := url.Parse(p); err != nil || u.Scheme == "" || u.Host == "" {
				v.warnf("telegram.proxy", "代理地址无效，应为 scheme://host:port")
			}
		}
	}
	if f := cfg.Feishu; f.Enabled {
		if strings.TrimSpace(f.AppID) == "" || strings.TrimSpace(f.AppSecret) == "" {
			v.warnf("feishu", "已启用但缺少 app_id 或 app_secret，通知不会发送")
		}
	}
	if q := cfg.QQ; q.Enabled {
		if strings.TrimSpace(q.AppID) == "" || strings.TrimSpace(q.AppSecret) == "" {
			v.warnf("qq", "已启用但缺少 app_id 或 app_secret，通知不会发送")
		}
	}

	w := cfg.Webhook
	if w.Enabled && len(w.URLs) == 0 {
		v.warnf("webhook.urls", "已启用但没有配置 URL，通知不会发送")
	}
	for i, u := range w.URLs {
		if !validHTTPURL(u) {
			v.warnf(fmt.Sprintf("webhook.urls[%d]", i), "不是合法的 http/https 地址")
		}
	}
	if w.TimeoutMs < 0 {
		v.warnf("webhook.timeout_ms", "不能为负数；当前会使用默认超时")
	}
	if w.RetryMax < 0 {
		v.warnf("webhook.retry_max", "不能为负数；当前不会重试")
	}

	b := cfg.Bark
	if b.Enabled && len(b.URLs) == 0 {
		v.warnf("bark.urls", "已启用但没有配置 URL，通知不会发送")
	}
	for i, u := range b.URLs {
		if !validHTTPURL(u) {
			v.warnf(fmt.Sprintf("bark.urls[%d]", i), "不是合法的 http/https 地址")
		}
	}

	if e := cfg.Email; e.Enabled {
		if strings.TrimSpace(e.SMTPHost) == "" || strings.TrimSpace(e.FromAddress) == "" || len(e.ToAddresses) == 0 {
			v.warnf("email", "已启用但缺少 smtp_host、from_address 或 to_addresses，通知不会发送")
		}
		if !validPort(e.SMTPPort) {
			v.warnf("email.smtp_port", "端口 %d 超出范围 1-65535", e.SMTPPort)
		}
	}
	if p := cfg.Pushplus; p.Enabled && strings.TrimSpace(p.Token) == "" {
		v.warnf("pushplus.token", "已启用但缺少 token，通知不会发送")
	}
}

func (v *validator) voiceGateway(vw VoWiFiConfig) {
	gw := vw.VoiceGateway
	listen := strings.TrimSpace(gw.SIP.Listen)
	if listen == "" {
		return // the gateway is off
	}
	if _, port, err := splitListenAddress(listen); err != nil || !validPort(port) {
		v.warnf("vowifi.voice_gateway.sip.listen", "监听地址无效，应为 主机:端口")
	}
	switch strings.ToLower(strings.TrimSpace(gw.SIP.Transport)) {
	case "", "udp", "tcp", "tls":
	default:
		v.warnf("vowifi.voice_gateway.sip.transport", "不支持的传输协议 %q，可选值: udp, tcp, tls", gw.SIP.Transport)
	}
	if ip := strings.TrimSpace(gw.SIP.ExternalIP); ip != "" && net.ParseIP(ip) == nil {
		v.warnf("vowifi.voice_gateway.sip.external_ip", "不是合法的 IP")
	}

	rtpMin, rtpMax := gw.Media.RTPPortMin, gw.Media.RTPPortMax
	if rtpMin != 0 || rtpMax != 0 {
		if !validPort(rtpMin) || !validPort(rtpMax) || rtpMin > rtpMax {
			v.warnf("vowifi.voice_gateway.media", "RTP 端口范围无效（rtp_port_min=%d, rtp_port_max=%d）", rtpMin, rtpMax)
		}
	}

	seen := make(map[string]int, len(gw.Users))
	for i, u := range gw.Users {
		path := fmt.Sprintf("vowifi.voice_gateway.users[%d]", i)
		name := strings.TrimSpace(u.Username)
		if name == "" {
			v.warnf(path+".username", "用户名为空")
			continue
		}
		if first, dup := seen[name]; dup {
			v.warnf(path+".username", "用户名与 users[%d] 重复", first)
		} else {
			seen[name] = i
		}
		if u.Password == "" {
			v.warnf(path+".password", "密码为空，该 SIP 用户无法通过认证")
		}
	}
}
