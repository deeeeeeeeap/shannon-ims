package config

import (
	yaml "go.yaml.in/yaml/v3"
)

const (
	legacyManagedNetworkKey = "disable_" + "network"
	managedNetworkKey       = "network_enabled"
)

// migrateLegacyManagedNetworkField rewrites the legacy network flag to the new
// network_enabled field and removes the old key from disk entirely.
func migrateLegacyManagedNetworkField(path string) error {
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
			if getMapValue(item, legacyManagedNetworkKey) == nil {
				continue
			}
			if getMapValue(item, managedNetworkKey) == nil {
				setMapBool(item, managedNetworkKey, false)
			}
			deleteMapKey(item, legacyManagedNetworkKey)
			changed = true
		}
		return changed, nil
	})
}
