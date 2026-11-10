package config

import (
	yaml "go.yaml.in/yaml/v3"
)

// deprecatedRuntimePathKeys 是不再由本地文件承载的运行时路径键。
// 这些路径每次按 IMEI 现解析,只活在内存;留在文件里只会被误用。
var deprecatedRuntimePathKeys = []string{
	"usb_path",
	"at_port",
	"manage_port",
	"interface",
	"qmi_device",
	"control_device",
	"audio_device",
}

// migrateDeprecatedRuntimePathFields 在加载时把磁盘配置里残留的运行时路径键物理删除,
// 使文件内容与零路径架构一致。无任何此类键时不写盘。
func migrateDeprecatedRuntimePathFields(path string) error {
	return mutateConfigDocument(path, false, func(root *yaml.Node) (bool, error) {
		devices := getMapValue(root, "devices")
		if devices == nil || devices.Kind != yaml.SequenceNode {
			return false, nil
		}

		changed := false
		for _, item := range devices.Content {
			if item == nil || item.Kind != yaml.MappingNode {
				continue
			}
			for _, key := range deprecatedRuntimePathKeys {
				if getMapValue(item, key) != nil {
					deleteMapKey(item, key)
					changed = true
				}
			}
		}
		return changed, nil
	})
}
