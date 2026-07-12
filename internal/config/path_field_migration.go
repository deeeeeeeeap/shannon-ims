package config

import (
	"fmt"
	"os"
	"path/filepath"

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
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}
	if len(doc.Content) == 0 {
		return nil
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}

	devices := getMapValue(root, "devices")
	if devices == nil || devices.Kind != yaml.SequenceNode {
		return nil
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
	if !changed {
		return nil
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("序列化配置文件失败: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return fmt.Errorf("写入迁移后的配置文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换迁移后的配置文件失败: %w", err)
	}

	return nil
}
