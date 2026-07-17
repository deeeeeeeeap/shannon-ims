package device

import (
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAddWorkerQMIManagedRebindsByIMEIWhenControlDeviceGone(t *testing.T) {
	// QMI 托管设备:配置 control_device 指向不存在节点,但配置了正确 IMEI;
	// 注入一块带该 IMEI 的新路径 QMI 硬件。bootstrap 应按 IMEI 取回新路径并采纳。

	originalDiscover := discoverQMIDevicesFn
	defer func() { discoverQMIDevicesFn = originalDiscover }()
	discoverQMIDevicesFn = func() ([]QMIDevice, error) {
		return []QMIDevice{
			{
				ControlPath:  "/dev/cdc-wdm-new-qmi",
				NetInterface: "wwan-new",
				USBPath:      "1-2.3",
				ATPort:       "/dev/ttyUSB-new",
			},
		}, nil
	}

	originalResolveQMI := resolveDiscoveredQMIDeviceFn
	defer func() { resolveDiscoveredQMIDeviceFn = originalResolveQMI }()
	resolveDiscoveredQMIDeviceFn = func(dev QMIDevice, timeout time.Duration, allowProbe bool) (QMIDevice, string) {
		if dev.ControlPath == "/dev/cdc-wdm-new-qmi" {
			return dev, "861234567890123"
		}
		return dev, ""
	}

	// 初始化 Pool
	p := NewPool(&config.Config{})
	t.Cleanup(func() { _ = p.Shutdown() })

	devCfg := config.DeviceConfig{
		ID:             "dev-qmi-1",
		DeviceBackend:  "qmi",
		ModemIMEI:      "861234567890123",
		ControlDevice:  "/dev/nonexistent-control-old",
		Interface:      "wwan-old",
		USBPath:        "1-9.9",
		NetworkEnabled: true, // hasManagedQMINetwork 的条件
	}

	worker, err := p.AddWorkerFromConfig(devCfg)
	require.NoError(t, err)
	require.NotNil(t, worker)
	require.Equal(t, "/dev/cdc-wdm-new-qmi", worker.Config.ControlDevice)
	require.Equal(t, "wwan-new", worker.Config.Interface)
	require.Equal(t, "1-2.3", worker.Config.USBPath)
	require.Same(t, worker, p.GetWorker(devCfg.ID))
}
