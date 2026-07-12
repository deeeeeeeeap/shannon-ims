// Package voice 提供 VoWiFi 语音通话功能
// 支持通过 Linphone 等 SIP 客户端接打电话
package sipgw

import (
	"fmt"
	"net"
	"strconv"
)

// Config 语音网关配置
type Config struct {
	Enabled      bool               `yaml:"enabled"`
	SIP          SIPConfig          `yaml:"sip"`
	Users        []UserConfig       `yaml:"users"`
	Media        MediaConfig        `yaml:"media"`
	LinphonePush LinphonePushConfig `yaml:"linphone_push"`
}

// LinphonePushConfig 推送配置
type LinphonePushConfig struct {
	LinphoneUser     string `yaml:"linphone_user"`
	LinphonePassword string `yaml:"linphone_password"`
}

// SIPConfig SIP 服务配置
type SIPConfig struct {
	Listen     string `yaml:"listen"`      // 监听地址，如 "0.0.0.0:5060"
	Transport  string `yaml:"transport"`   // 传输协议: udp/tcp/tls
	Realm      string `yaml:"realm"`       // SIP 认证域，如 "vohive.local"
	ExternalIP string `yaml:"external_ip"` // 公网 IP (可选，用于 NAT)
}

// UserConfig 用户配置
type UserConfig struct {
	Username    string `yaml:"username"`     // SIP 用户名
	Password    string `yaml:"password"`     // SIP 密码
	DisplayName string `yaml:"display_name"` // 显示名称
	DeviceID    string `yaml:"device_id"`    // 绑定的设备 ID
}

// MediaConfig 媒体配置
type MediaConfig struct {
	RTPPortMin int      `yaml:"rtp_port_min"` // RTP 端口范围起始，如 10000
	RTPPortMax int      `yaml:"rtp_port_max"` // RTP 端口范围结束，如 20000
	Codecs     []string `yaml:"codecs"`       // 支持的编解码器列表
}

func (c Config) Validate() error {
	if c.SIP.Listen == "" {
		return fmt.Errorf("sip.listen 不能为空")
	}
	_, portStr, err := net.SplitHostPort(c.SIP.Listen)
	if err != nil {
		return fmt.Errorf("sip.listen 格式错误: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("sip.listen 端口无效: %s", portStr)
	}
	if c.SIP.Realm == "" {
		return fmt.Errorf("sip.realm 不能为空")
	}
	if c.Media.RTPPortMin > 0 && c.Media.RTPPortMin%2 != 0 {
		return fmt.Errorf("media.rtp_port_min 必须为偶数")
	}
	if c.Media.RTPPortMin > 0 && c.Media.RTPPortMax > 0 && c.Media.RTPPortMax <= c.Media.RTPPortMin+1 {
		return fmt.Errorf("media.rtp_port_max 必须大于 rtp_port_min+1")
	}
	return nil
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		SIP: SIPConfig{
			Listen:    "0.0.0.0:5060",
			Transport: "udp",
			Realm:     "vohive.local",
		},
		Users: []UserConfig{},
		Media: MediaConfig{
			RTPPortMin: 10000,
			RTPPortMax: 20000,
			Codecs:     []string{"PCMU/8000", "PCMA/8000"},
		},
		LinphonePush: LinphonePushConfig{
			LinphoneUser:     "",
			LinphonePassword: "",
		},
	}
}
