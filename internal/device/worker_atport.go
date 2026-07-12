package device

import "strings"

// ResolvedATPort 返回当前设备真实可用的 AT 口,统一的内存兜底链:
// 运行时 Config.ATPort → Config.ManagePort → Modem 在设备获取时刻的快照端口。
// 零路径架构下持久化侧不再承载路径,因此这里绝不读配置文件,只读内存。
func (w *Worker) ResolvedATPort() string {
	if w == nil {
		return ""
	}
	if v := strings.TrimSpace(w.Config.ATPort); v != "" {
		return v
	}
	if v := strings.TrimSpace(w.Config.ManagePort); v != "" {
		return v
	}
	if w.Modem != nil {
		return strings.TrimSpace(w.Modem.ATPort())
	}
	return ""
}
