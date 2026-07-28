package driver

import (
	"fmt"

	"github.com/songgao/water"
)

// TUNDevice 封装 water 库的 TUN 接口
// 使用成熟的第三方库处理 TUN 设备，避免 Go netpoll 兼容性问题
type TUNDevice struct {
	iface *water.Interface
	Name  string
}

// NewTUNDevice 使用 water 库创建 TUN 设备
// 如果同名设备已存在，先尝试删除旧设备
func NewTUNDevice(name string) (*TUNDevice, error) {
	// 尝试删除可能残留的同名 TUN 设备
	// 这可以解决上一次异常退出导致设备未清理的问题
	if name != "" {
		nt := NewNetTools()
		if err := nt.DeleteLink(name); err == nil {
			// 设备已删除，等待系统释放资源
			// 不需要日志，因为这只是预防性清理
		}
	}

	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 设备失败: %v", err)
	}

	return &TUNDevice{
		iface: iface,
		Name:  iface.Name(),
	}, nil
}

// Read 从 TUN 设备读取数据
func (t *TUNDevice) Read(p []byte) (n int, err error) {
	return t.iface.Read(p)
}

// Write 向 TUN 设备写入数据
func (t *TUNDevice) Write(p []byte) (n int, err error) {
	return t.iface.Write(p)
}

// Close 关闭 TUN 设备
func (t *TUNDevice) Close() error {
	return t.iface.Close()
}

// DeviceName 返回 TUN 设备名称
func (t *TUNDevice) DeviceName() string {
	return t.Name
}
