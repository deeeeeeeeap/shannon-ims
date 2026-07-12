package config

import (
	"fmt"
	"os"
	"path/filepath"

	yaml "go.yaml.in/yaml/v3"
)

// AddProxyInstanceInFile 添加一个代理实例到配置文件
func AddProxyInstanceInFile(path string, instance ProxyInstance) error {
	return updateProxyInFile(path, func(proxy *yaml.Node) error {
		instances := ensureSequence(proxy, "instances")
		if findNodeByID(instances, instance.ID) != nil {
			return fmt.Errorf("代理实例已存在: %s", instance.ID)
		}
		instances.Content = append(instances.Content, proxyInstanceToNode(instance))
		return nil
	})
}

// UpdateProxyInstanceInFile 更新指定 ID 的代理实例
func UpdateProxyInstanceInFile(path string, id string, newInstance ProxyInstance) error {
	return updateProxyInFile(path, func(proxy *yaml.Node) error {
		instances := ensureSequence(proxy, "instances")
		n := findNodeByID(instances, id)
		if n == nil {
			return fmt.Errorf("代理实例未找到: %s", id)
		}

		setMapScalar(n, "id", newInstance.ID)
		setMapScalar(n, "name", newInstance.Name)
		setMapScalar(n, "device_id", newInstance.DeviceID)
		setMapBool(n, "enabled", newInstance.Enabled)
		setMapScalar(n, "mode", newInstance.Mode)
		setMapScalar(n, "listen_addr", newInstance.ListenAddr)
		setMapInt(n, "listen_port", newInstance.ListenPort)
		setMapBool(n, "auth_enabled", newInstance.AuthEnabled)
		setMapScalar(n, "username", newInstance.Username)
		setMapScalar(n, "password", newInstance.Password)
		return nil
	})
}

// DeleteProxyInstanceInFile 删除指定 ID 的代理实例
func DeleteProxyInstanceInFile(path string, id string) error {
	return updateProxyInFile(path, func(proxy *yaml.Node) error {
		instances := ensureSequence(proxy, "instances")
		return deleteNodeByID(instances, id)
	})
}

// UpdateProxyConfigInFile 批量更新整个代理配置
// 会完全替换现有的 proxy.instances 列表
func UpdateProxyConfigInFile(path string, cfg ProxyConfig) error {
	return updateProxyInFile(path, func(proxy *yaml.Node) error {
		instancesSeq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, inst := range cfg.Instances {
			instancesSeq.Content = append(instancesSeq.Content, proxyInstanceToNode(inst))
		}
		setMapNode(proxy, "instances", instancesSeq)
		return nil
	})
}

// updateProxyInFile 通用的代理配置更新函数
func updateProxyInFile(path string, mutate func(*yaml.Node) error) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	if len(doc.Content) == 0 {
		return fmt.Errorf("配置文件为空")
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("配置文件结构错误")
	}

	proxy := getMapValue(root, "proxy")
	if proxy == nil {
		proxy = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setMapNode(root, "proxy", proxy)
	}

	if err := mutate(proxy); err != nil {
		return err
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
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换配置文件失败: %w", err)
	}

	_ = ReloadFromFile()
	return nil
}

// ensureSequence 确保指定 key 对应的节点是一个序列
func ensureSequence(parent *yaml.Node, key string) *yaml.Node {
	seq := getMapValue(parent, key)
	if seq == nil || seq.Kind != yaml.SequenceNode {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setMapNode(parent, key, seq)
	}
	return seq
}

// findNodeByID 在序列中查找指定 ID 的节点
func findNodeByID(seq *yaml.Node, id string) *yaml.Node {
	for _, item := range seq.Content {
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		if v := getMapScalar(item, "id"); v == id {
			return item
		}
	}
	return nil
}

// deleteNodeByID 从序列中删除指定 ID 的节点
func deleteNodeByID(seq *yaml.Node, id string) error {
	for i, item := range seq.Content {
		if item == nil || item.Kind != yaml.MappingNode {
			continue
		}
		if v := getMapScalar(item, "id"); v == id {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("未找到 ID: %s", id)
}

// proxyInstanceToNode 将 ProxyInstance 转换为 YAML 节点
func proxyInstanceToNode(p ProxyInstance) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}

	appendMapScalar(m, "id", p.ID)
	if p.Name != "" {
		appendMapScalar(m, "name", p.Name)
	}
	appendMapScalar(m, "device_id", p.DeviceID)
	appendMapBool(m, "enabled", p.Enabled)
	if p.Mode != "" {
		appendMapScalar(m, "mode", p.Mode)
	}
	if p.ListenAddr != "" {
		appendMapScalar(m, "listen_addr", p.ListenAddr)
	}
	appendMapInt(m, "listen_port", p.ListenPort)
	appendMapBool(m, "auth_enabled", p.AuthEnabled)
	if p.Username != "" {
		appendMapScalar(m, "username", p.Username)
	}
	if p.Password != "" {
		appendMapScalar(m, "password", p.Password)
	}
	return m
}
