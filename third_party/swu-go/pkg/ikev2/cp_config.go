package ikev2

import (
	"net"
)

// CPConfig 从 CP 载荷中解析出的配置信息
type CPConfig struct {
	// IPv4
	IPv4Addresses []net.IP
	IPv4DNS       []net.IP
	IPv4PCSCF     []net.IP

	// IPv6
	IPv6Addresses []net.IP
	IPv6Prefix    uint8 // 通常为 64
	IPv6DNS       []net.IP
	IPv6PCSCF     []net.IP
}

// ParseCPConfig 从 CP 载荷解析配置
func ParseCPConfig(cp *EncryptedPayloadCP) *CPConfig {
	cfg := &CPConfig{}

	for _, attr := range cp.Attributes {
		switch attr.Type {
		case INTERNAL_IP4_ADDRESS:
			if len(attr.Value) >= 4 {
				cfg.IPv4Addresses = append(cfg.IPv4Addresses, net.IP(attr.Value[:4]))
			}
		case INTERNAL_IP4_DNS:
			if len(attr.Value) >= 4 {
				cfg.IPv4DNS = append(cfg.IPv4DNS, net.IP(attr.Value[:4]))
			}
		case P_CSCF_IP4_ADDRESS:
			if len(attr.Value) >= 4 {
				cfg.IPv4PCSCF = append(cfg.IPv4PCSCF, net.IP(attr.Value[:4]))
			}
		case INTERNAL_IP6_ADDRESS:
			// IPv6 地址格式: 16 字节 IP + 1 字节前缀长度
			if len(attr.Value) >= 17 {
				cfg.IPv6Addresses = append(cfg.IPv6Addresses, net.IP(attr.Value[:16]))
				cfg.IPv6Prefix = attr.Value[16]
			} else if len(attr.Value) >= 16 {
				cfg.IPv6Addresses = append(cfg.IPv6Addresses, net.IP(attr.Value[:16]))
			}
		case INTERNAL_IP6_DNS:
			if len(attr.Value) >= 16 {
				cfg.IPv6DNS = append(cfg.IPv6DNS, net.IP(attr.Value[:16]))
			}
		case P_CSCF_IP6_ADDRESS:
			if len(attr.Value) >= 16 {
				cfg.IPv6PCSCF = append(cfg.IPv6PCSCF, net.IP(attr.Value[:16]))
			}
		case ASSIGNED_PCSCF_IP6_ADDRESS:
			if len(attr.Value) >= 16 {
				cfg.IPv6PCSCF = append(cfg.IPv6PCSCF, net.IP(attr.Value[:16]))
			}
		}
	}

	return cfg
}

// HasIPv4 检查是否有 IPv4 配置
func (c *CPConfig) HasIPv4() bool {
	return len(c.IPv4Addresses) > 0
}

// HasIPv6 检查是否有 IPv6 配置
func (c *CPConfig) HasIPv6() bool {
	return len(c.IPv6Addresses) > 0
}
