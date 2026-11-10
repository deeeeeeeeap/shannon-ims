package backend

import (
	"fmt"
	"strings"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/modem"
	"github.com/1239t/vohive/pkg/logger"
)

// 后端模式常量
const (
	BackendAT   = config.DeviceBackendAT
	BackendQMI  = config.DeviceBackendQMI
	BackendMBIM = config.DeviceBackendMBIM
)

// NormalizeBackendMode 标准化后端模式字符串。
// 未知取值按 AT 处理以兼容已部署的配置；需要拒绝未知取值的入口（API 保存、
// 启动期配置校验）必须先调用 ValidateBackendMode。
func NormalizeBackendMode(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "", BackendAT:
		return BackendAT // 默认 AT 模式
	case BackendQMI:
		return BackendQMI
	case BackendMBIM:
		return BackendMBIM
	default:
		return BackendAT
	}
}

// ValidateBackendMode 验证后端模式是否有效（空值表示未配置，合法）。
// 必须在规范化之前判断：NormalizeBackendMode 会把未知取值折叠成 AT。
func ValidateBackendMode(in string) error {
	return config.ValidateDeviceBackend(in)
}

// NewBackend 根据配置模式创建对应后端实例的工厂方法
// mode: "at" | "qmi"
// controlPath: QMI 控制设备路径（qmi 模式必须）
// m: modem.Manager（at 模式必须）
// source: QMI Core 资源源（qmi 模式必须）
func NewBackend(mode, controlPath string, m *modem.Manager, source QMISource, mbimSource MBIMSource) (DeviceBackend, error) {
	mode = NormalizeBackendMode(mode)

	switch mode {
	case BackendAT:
		if m == nil {
			return nil, fmt.Errorf("AT 模式需要 modem.Manager")
		}
		logger.Info("[backend] 使用 AT 后端模式")
		return NewATBackend(m), nil

	case BackendQMI:
		b, err := NewQMIBackend(controlPath, source)
		if err != nil {
			return nil, fmt.Errorf("QMI 后端初始化失败: %w", err)
		}
		logger.Info("[backend] 使用 QMI 后端模式", "control_path", controlPath)
		return b, nil

	case BackendMBIM:
		if mbimSource == nil {
			return nil, fmt.Errorf("MBIM 模式需要 MBIMSource")
		}
		logger.Info("[backend] 使用 MBIM 后端模式", "control_path", controlPath)
		return NewMBIMBackend(controlPath, mbimSource), nil

	default:
		return nil, fmt.Errorf("不支持的后端模式: %s", mode)
	}
}
