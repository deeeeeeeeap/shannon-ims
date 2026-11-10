package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/1239t/vohive/pkg/logger"
	yaml "go.yaml.in/yaml/v3"
)

// configFileMu serialises every read-modify-write cycle on the configuration
// file. API handlers, the device pool and the startup migrations all rewrite
// the same YAML document; without one shared lock two writers can interleave
// and silently drop each other's section.
var configFileMu sync.Mutex

// mutateConfigFile runs one read-modify-write cycle under configFileMu.
// mutate receives the current file content and returns the new content; when
// changed is false nothing is written.
func mutateConfigFile(path string, mutate func(data []byte) (out []byte, changed bool, err error)) error {
	configFileMu.Lock()
	defer configFileMu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	out, changed, err := mutate(data)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return writeConfigFileAtomic(path, out)
}

// mutateConfigDocument is mutateConfigFile for callers that edit the YAML node
// tree (which keeps key order and comments). mutate receives the root mapping.
// With requireRoot an empty or non-mapping document is an error; otherwise it
// is left untouched, which is what the load-time migrations need.
func mutateConfigDocument(path string, requireRoot bool, mutate func(root *yaml.Node) (changed bool, err error)) error {
	return mutateConfigFile(path, func(data []byte) ([]byte, bool, error) {
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return nil, false, fmt.Errorf("解析配置文件失败: %w", err)
		}
		if len(doc.Content) == 0 {
			if requireRoot {
				return nil, false, fmt.Errorf("配置文件为空")
			}
			return nil, false, nil
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode {
			if requireRoot {
				return nil, false, fmt.Errorf("配置文件结构错误")
			}
			return nil, false, nil
		}

		changed, err := mutate(root)
		if err != nil || !changed {
			return nil, false, err
		}
		out, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, false, fmt.Errorf("序列化配置文件失败: %w", err)
		}
		return out, true, nil
	})
}

// writeConfigFileAtomic replaces path with data so that readers and a crash at
// any point observe either the old or the new document, never a partial one.
// The temporary file gets a unique name: a fixed "<path>.tmp" would let two
// writers truncate each other's half-written output.
func writeConfigFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	// The file carries credentials: keep it owner-only regardless of umask.
	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("替换配置文件失败: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir makes the rename durable. Failure is not fatal: the new content is
// already visible and some filesystems do not support fsync on directories.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// reloadAfterWrite refreshes the in-memory configuration after a successful
// write. The write itself already succeeded, so a reload failure is reported
// instead of being returned to the caller.
func reloadAfterWrite(path string) {
	if err := ReloadFromFile(); err != nil {
		logger.Warn("配置已写入磁盘，但重新加载到内存失败", "path", path, "err", err)
	}
}
