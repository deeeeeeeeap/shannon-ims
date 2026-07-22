package config

import (
	"sync"

	"github.com/1239t/vohive/pkg/logger"
)

var (
	globalConfig *Config
	configMu     sync.RWMutex
	configPath   string
	secureWeb    bool
)

// InitGlobalManager 初始化全局配置管理器，将首次从文件加载到内存
func InitGlobalManager(path string) error {
	configMu.Lock()
	configPath = path
	secureWeb = false
	configMu.Unlock()
	return ReloadFromFile()
}

// InitGlobalManagerForStartup is the production entry point. It validates the
// Web authentication boundary before publishing the configuration globally.
func InitGlobalManagerForStartup(path string) error {
	cfg, err := LoadForStartup(path)
	if err != nil {
		return err
	}
	configMu.Lock()
	configPath = path
	globalConfig = cfg
	secureWeb = true
	configMu.Unlock()
	logger.Info("配置文件已从磁盘加载到内存", "path", path)
	return nil
}

// ReloadFromFile 从磁盘重新加载最新配置到内存，通常在任何更新配置的动作后主动调用
func ReloadFromFile() error {
	configMu.RLock()
	path := configPath
	requireSecureWeb := secureWeb
	configMu.RUnlock()
	if path == "" {
		return nil
	}
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	if requireSecureWeb {
		if err := ValidateWebCredentials(cfg.Web); err != nil {
			return err
		}
	}
	configMu.Lock()
	globalConfig = cfg
	configMu.Unlock()
	logger.Info("配置文件已从磁盘热加载到内存", "path", path)
	return nil
}

// GetConfig 获取当前处于内存中的全局配置。为保障一致性，不可在外部直接修改返回值。
func GetConfig() *Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return cloneConfig(globalConfig)
}

func cloneConfig(src *Config) *Config {
	if src == nil {
		return &Config{}
	}
	dst := *src
	dst.Devices = append([]DeviceConfig(nil), src.Devices...)
	for i := range dst.Devices {
		if src.Devices[i].USBNetMode != nil {
			mode := *src.Devices[i].USBNetMode
			dst.Devices[i].USBNetMode = &mode
		}
	}
	dst.Proxy.Instances = append([]ProxyInstance(nil), src.Proxy.Instances...)
	dst.Feishu.ChatIDs = append([]string(nil), src.Feishu.ChatIDs...)
	dst.Webhook.URLs = append([]string(nil), src.Webhook.URLs...)
	if src.Webhook.Headers != nil {
		dst.Webhook.Headers = make(map[string]string, len(src.Webhook.Headers))
		for key, value := range src.Webhook.Headers {
			dst.Webhook.Headers[key] = value
		}
	}
	dst.Bark.URLs = append([]string(nil), src.Bark.URLs...)
	dst.Email.ToAddresses = append([]string(nil), src.Email.ToAddresses...)
	dst.VoWiFi.VoiceGateway.Users = append([]VoWiFiVoiceUserConfig(nil), src.VoWiFi.VoiceGateway.Users...)
	dst.VoWiFi.VoiceGateway.Media.Codecs = append([]string(nil), src.VoWiFi.VoiceGateway.Media.Codecs...)
	return &dst
}

// GetConfigPath 返回当前全局配置文件路径，供需要直接读写配置文件的场景使用
// （如设备恢复后回写发现到的物理路径）。
func GetConfigPath() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return configPath
}

// ListDevices 快捷获取内存中的设备列表，替代原 ListDevicesFromFile 造成的高频 IO
func ListDevices() []DeviceConfig {
	return GetConfig().Devices
}

// GetDeviceByID 快捷获取内存中指定 ID 的设备
func GetDeviceByID(id string) (*DeviceConfig, error) {
	devices := ListDevices()
	for i := range devices {
		if devices[i].ID == id {
			return &devices[i], nil
		}
	}
	return nil, nil // not found
}
