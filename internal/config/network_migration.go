package config

import (
	"fmt"
	"os"
	"path/filepath"

	yaml "go.yaml.in/yaml/v3"
)

const (
	legacyManagedNetworkKey = "disable_" + "network"
	managedNetworkKey       = "network_enabled"
)

// migrateLegacyManagedNetworkField rewrites the legacy network flag to the new
// network_enabled field and removes the old key from disk entirely.
func migrateLegacyManagedNetworkField(path string) error {
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
		if getMapValue(item, legacyManagedNetworkKey) == nil {
			continue
		}
		if getMapValue(item, managedNetworkKey) == nil {
			setMapBool(item, managedNetworkKey, false)
		}
		deleteMapKey(item, legacyManagedNetworkKey)
		changed = true
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
