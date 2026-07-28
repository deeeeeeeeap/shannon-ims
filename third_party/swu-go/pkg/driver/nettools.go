package driver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/iniwex5/netlink"
	"golang.org/x/sys/unix"
)

// NetTools 封装网络配置操作
type NetTools struct{}

// NewNetTools 创建 NetTools 实例
func NewNetTools() *NetTools {
	return &NetTools{}
}

// NetToolError 封装网络操作错误
type NetToolError struct {
	Op   string // 操作描述
	Args string // 参数信息
	Err  error  // 底层错误
}

func (e *NetToolError) Error() string {
	if e.Args == "" {
		return fmt.Sprintf("%s 失败: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s %s 失败: %v", e.Op, e.Args, e.Err)
}

func (e *NetToolError) Unwrap() error { return e.Err }

// wrapErr 封装错误
func wrapErr(op, args string, err error) error {
	if err == nil {
		return nil
	}
	return &NetToolError{Op: op, Args: args, Err: err}
}

// getLink 根据接口名获取 Link 对象
func getLink(iface string) (netlink.Link, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("获取接口 %s 失败: %v", iface, err)
	}
	return link, nil
}

// GetLink 根据接口名获取 Link 对象（导出方法）
func (n *NetTools) GetLink(iface string) (netlink.Link, error) {
	return getLink(iface)
}

// SetLinkUp 启用网络接口
func (n *NetTools) SetLinkUp(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set up", iface, err)
	}
	return wrapErr("link set up", iface, netlink.LinkSetUp(link))
}

// SetLinkDown 禁用网络接口
func (n *NetTools) SetLinkDown(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set down", iface, err)
	}
	return wrapErr("link set down", iface, netlink.LinkSetDown(link))
}

// DeleteLink 删除网络设备（如 TUN）
func (n *NetTools) DeleteLink(iface string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link del", iface, err)
	}
	return wrapErr("link del", iface, netlink.LinkDel(link))
}

// SetMTU 设置接口 MTU
func (n *NetTools) SetMTU(iface string, mtu int) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("link set mtu", fmt.Sprintf("%s %d", iface, mtu), err)
	}
	return wrapErr("link set mtu", fmt.Sprintf("%s %d", iface, mtu), netlink.LinkSetMTU(link, mtu))
}

// AddAddress 添加 IPv4 地址（例如 "10.0.0.1/24"）
func (n *NetTools) AddAddress(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	return wrapErr("addr add", fmt.Sprintf("%s dev %s", cidr, iface), netlink.AddrAdd(link, addr))
}

// DelAddress 删除 IPv4 地址
func (n *NetTools) DelAddress(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	return wrapErr("addr del", fmt.Sprintf("%s dev %s", cidr, iface), netlink.AddrDel(link, addr))
}

// AddAddress6 添加 IPv6 地址（例如 "2001:db8::1/64"），带重试机制
func (n *NetTools) AddAddress6(iface string, cidr string) error {
	link, err := getLink(iface)
	if err != nil {
		return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), fmt.Errorf("解析地址失败: %v", err))
	}

	// 设置 nodad 标志（禁用 DAD）
	addr.Flags = addr.Flags | unix.IFA_F_NODAD

	// 重试机制：设备刚创建时可能需要等待
	var lastErr error
	for i := 0; i < 5; i++ {
		err = netlink.AddrAdd(link, addr)
		if err == nil {
			return nil
		}
		lastErr = err
		// 如果是 Invalid argument 错误，等待后重试
		if i < 4 {
			time.Sleep(80 * time.Millisecond)
		}
	}
	return wrapErr("addr add -6", fmt.Sprintf("%s dev %s", cidr, iface), lastErr)
}

// DelAddress6 删除 IPv6 地址
func (n *NetTools) DelAddress6(iface string, cidr string) error {
	return n.DelAddress(iface, cidr)
}

// AddRoute 添加 IPv4 路由
func (n *NetTools) AddRoute(cidr string, gw string, iface string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route add", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst: dst,
	}

	// 设置网关
	if gw != "" {
		route.Gw = net.ParseIP(gw)
		if route.Gw == nil {
			return wrapErr("route add", cidr, fmt.Errorf("无效的网关地址: %s", gw))
		}
	}

	// 设置设备
	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route add", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	// 忽略路由已存在错误（多设备可能共享 P-CSCF 等目标地址）
	err = netlink.RouteAdd(route)
	if err != nil && isRouteExists(err) {
		return nil
	}
	return wrapErr("route add", cidr, err)
}

// DelRoute 删除 IPv4 路由
func (n *NetTools) DelRoute(cidr string, gw string, iface string) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route del", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst: dst,
	}

	if gw != "" {
		route.Gw = net.ParseIP(gw)
	}

	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route del", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	// 忽略路由不存在错误（可能已被其他设备会话删除）
	err = netlink.RouteDel(route)
	if err != nil && isRouteNotFound(err) {
		return nil
	}
	return wrapErr("route del", cidr, err)
}

// AddRoute6 添加 IPv6 路由
func (n *NetTools) AddRoute6(cidr string, gw string, iface string) error {
	return n.AddRoute(cidr, gw, iface)
}

// DelRoute6 删除 IPv6 路由
func (n *NetTools) DelRoute6(cidr string, gw string, iface string) error {
	return n.DelRoute(cidr, gw, iface)
}

// isRouteExists 判断是否为路由已存在错误 (EEXIST)
func isRouteExists(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EEXIST
	}
	return false
}

// isRouteNotFound 判断是否为路由不存在错误 (ESRCH)
func isRouteNotFound(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ESRCH
	}
	return false
}

// isRuleExists 判断是否为规则已存在错误 (EEXIST)
func isRuleExists(err error) bool {
	return isRouteExists(err)
}

// AddRouteTable 在指定路由表中添加路由（用于策略路由）
func (n *NetTools) AddRouteTable(cidr string, iface string, table int) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route add table", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst:   dst,
		Table: table,
	}

	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route add table", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	// 忽略路由已存在错误
	err = netlink.RouteAdd(route)
	if err != nil && isRouteExists(err) {
		return nil
	}
	return wrapErr("route add table", cidr, err)
}

// DelRouteTable 从指定路由表中删除路由
func (n *NetTools) DelRouteTable(cidr string, iface string, table int) error {
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return wrapErr("route del table", cidr, fmt.Errorf("解析目标地址失败: %v", err))
	}

	route := &netlink.Route{
		Dst:   dst,
		Table: table,
	}

	if iface != "" {
		link, err := getLink(iface)
		if err != nil {
			return wrapErr("route del table", cidr, err)
		}
		route.LinkIndex = link.Attrs().Index
	}

	// 忽略路由不存在错误
	err = netlink.RouteDel(route)
	if err != nil && isRouteNotFound(err) {
		return nil
	}
	return wrapErr("route del table", cidr, err)
}

// AddRule 添加策略路由规则：from <srcCIDR> lookup <table>
func (n *NetTools) AddRule(srcCIDR string, table int) error {
	_, src, err := net.ParseCIDR(srcCIDR)
	if err != nil {
		return wrapErr("rule add", srcCIDR, fmt.Errorf("解析源地址失败: %v", err))
	}

	rule := netlink.NewRule()
	rule.Src = src
	rule.Table = table
	if src.IP.To4() == nil {
		rule.Family = netlink.FAMILY_V6
	} else {
		rule.Family = netlink.FAMILY_V4
	}

	// 清理旧规则 (防止 Table ID 变更导致残留规则指向无效表)
	// 查找所有源地址匹配的规则并删除
	family := netlink.FAMILY_V4
	if src.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	if rules, err := netlink.RuleList(family); err == nil {
		for _, r := range rules {
			if r.Src != nil && r.Src.String() == src.String() {
				// 忽略错误，尽可能清理
				_ = netlink.RuleDel(&r)
			}
		}
	}

	err = netlink.RuleAdd(rule)
	if err != nil && isRuleExists(err) {
		return nil
	}
	return wrapErr("rule add", fmt.Sprintf("from %s lookup %d", srcCIDR, table), err)
}

// DelRule 删除策略路由规则
func (n *NetTools) DelRule(srcCIDR string, table int) error {
	_, src, err := net.ParseCIDR(srcCIDR)
	if err != nil {
		return wrapErr("rule del", srcCIDR, fmt.Errorf("解析源地址失败: %v", err))
	}

	rule := netlink.NewRule()
	rule.Src = src
	rule.Table = table

	// 忽略规则不存在错误
	err = netlink.RuleDel(rule)
	if err != nil && isRouteNotFound(err) {
		return nil
	}
	return wrapErr("rule del", fmt.Sprintf("from %s lookup %d", srcCIDR, table), err)
}

// AddInputRule 添加基于入站接口的策略路由规则：iif <iface> lookup <table>
func (n *NetTools) AddInputRule(iface string, table int) error {
	// 添加 IPv4 规则
	rule4 := netlink.NewRule()
	rule4.IifName = iface
	rule4.Table = table
	rule4.Family = netlink.FAMILY_V4

	// 清理旧规则 (IPv4)
	if rules, err := netlink.RuleList(netlink.FAMILY_V4); err == nil {
		for _, r := range rules {
			if r.IifName == iface {
				_ = netlink.RuleDel(&r)
			}
		}
	}

	if err := netlink.RuleAdd(rule4); err != nil && !isRuleExists(err) {
		return wrapErr("rule add v4", fmt.Sprintf("iif %s lookup %d", iface, table), err)
	}

	// 添加 IPv6 规则
	rule6 := netlink.NewRule()
	rule6.IifName = iface
	rule6.Table = table
	rule6.Family = netlink.FAMILY_V6

	// 清理旧规则 (IPv6)
	if rules, err := netlink.RuleList(netlink.FAMILY_V6); err == nil {
		for _, r := range rules {
			if r.IifName == iface {
				_ = netlink.RuleDel(&r)
			}
		}
	}

	if err := netlink.RuleAdd(rule6); err != nil && !isRuleExists(err) {
		return wrapErr("rule add v6", fmt.Sprintf("iif %s lookup %d", iface, table), err)
	}

	return nil
}

// DelInputRule 删除基于入站接口的策略路由规则
func (n *NetTools) DelInputRule(iface string, table int) error {
	rule := netlink.NewRule()
	rule.IifName = iface
	rule.Table = table

	// 忽略规则不存在错误
	err := netlink.RuleDel(rule)
	if err != nil && isRouteNotFound(err) {
		return nil
	}
	return wrapErr("rule del", fmt.Sprintf("iif %s lookup %d", iface, table), err)
}

// FlushRules (O(1) 优化) 批量清除与特定表和接口相关的策略路由规则，防止设备离线雪崩
func (n *NetTools) FlushRules(table int, iface string) error {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if r.Table == table || r.IifName == iface {
				_ = netlink.RuleDel(&r)
			}
		}
	}
	return nil
}

// CleanConflictRoutes 删除 main 表中指向非指定接口的冲突路由
// 用于清理其他设备或旧 session 残留的 P-CSCF 路由（如 dev ens2），
// 避免这些路由抢占策略路由导致流量走物理接口而非 XFRM 隧道。
// family: netlink.FAMILY_V4 或 netlink.FAMILY_V6
func (n *NetTools) CleanConflictRoutes(cidrs []string, keepIface string, family int) {
	kLink, _ := getLink(keepIface)
	var keepIdx int
	if kLink != nil {
		keepIdx = kLink.Attrs().Index
	}

	for _, cidr := range cidrs {
		// 跳过默认路由
		if cidr == "::/0" || cidr == "0.0.0.0/0" {
			continue
		}
		// 去掉 /128 或 /32 后缀以获取纯 IP，然后构造精确匹配的 CIDR
		target := strings.TrimSuffix(strings.TrimSuffix(cidr, "/128"), "/32")
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			// 尝试将纯 IP 转为 CIDR
			ip := net.ParseIP(target)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				dst = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				dst = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}

		// 查询 main 表中到该目的地的路由
		filter := &netlink.Route{
			Dst:   dst,
			Table: unix.RT_TABLE_MAIN,
		}
		routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
		if err != nil || len(routes) == 0 {
			continue
		}

		// 删除不指向 keepIface 的路由
		for _, r := range routes {
			if r.LinkIndex != keepIdx {
				_ = netlink.RouteDel(&r)
			}
		}
	}
}

// SetSysctl 设置内核参数（替代 exec.Command("sysctl", "-w", ...)）
// key 格式如 "net.ipv6.conf.ims-ec20_1.disable_ipv6"
func (n *NetTools) SetSysctl(key, value string) error {
	// 将 dot 分隔的 key 转为 /proc/sys/ 路径
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		return fmt.Errorf("设置 sysctl %s=%s 失败: %v", key, value, err)
	}
	return nil
}
