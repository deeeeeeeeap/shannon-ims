package driver

import (
	"fmt"
	"runtime"

	"github.com/iniwex5/netlink"
	"github.com/vishvananda/netns"
)

// NetNS 表示一个网络命名空间
type NetNS struct {
	name   string
	handle netns.NsHandle // 新命名空间句柄
	origin netns.NsHandle // 原始命名空间句柄，用于恢复
}

// NewNetNS 创建新的网络命名空间
func NewNetNS(name string) (*NetNS, error) {
	// 1. 保存当前命名空间
	origin, err := netns.Get()
	if err != nil {
		return nil, fmt.Errorf("获取原始 netns 失败: %v", err)
	}

	// 2. 创建命名空间
	handle, err := netns.NewNamed(name)
	if err != nil {
		origin.Close()
		return nil, fmt.Errorf("创建 netns %s 失败: %v", name, err)
	}

	return &NetNS{
		name:   name,
		handle: handle,
		origin: origin,
	}, nil
}

// Enter 进入网络命名空间
// 注意: 需要 CAP_SYS_ADMIN 权限
func (ns *NetNS) Enter() error {
	// 锁定当前 goroutine 到 OS 线程
	runtime.LockOSThread()

	if !ns.handle.IsOpen() {
		runtime.UnlockOSThread()
		return fmt.Errorf("netns 句柄不可用")
	}
	if !ns.origin.IsOpen() {
		runtime.UnlockOSThread()
		return fmt.Errorf("原始 netns 句柄不可用")
	}

	if err := netns.Set(ns.handle); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("切换 netns 失败: %v", err)
	}
	return nil
}

// Exit 退出网络命名空间，恢复到原始命名空间
func (ns *NetNS) Exit() error {
	if ns.origin.IsOpen() {
		if err := netns.Set(ns.origin); err != nil {
			runtime.UnlockOSThread()
			return fmt.Errorf("恢复原始 netns 失败: %v", err)
		}
	}
	runtime.UnlockOSThread()
	return nil
}

// Delete 删除网络命名空间
func (ns *NetNS) Delete() error {
	if ns.handle.IsOpen() {
		ns.handle.Close()
	}
	if ns.origin.IsOpen() {
		ns.origin.Close()
	}

	if err := netns.DeleteNamed(ns.name); err != nil {
		return fmt.Errorf("删除 netns %s 失败: %v", ns.name, err)
	}

	return nil
}

// RunCommand 在指定命名空间内执行函数
// 注意: 此方法现在接受一个函数而非命令行参数
func (ns *NetNS) RunInNS(fn func() error) error {
	if err := ns.Enter(); err != nil {
		return err
	}
	defer ns.Exit()
	return fn()
}

// MoveInterfaceToNetNS 将网络接口移动到命名空间
func (ns *NetNS) MoveInterfaceToNetNS(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("获取接口 %s 失败: %v", ifname, err)
	}

	if err := netlink.LinkSetNsFd(link, int(ns.handle)); err != nil {
		return fmt.Errorf("移动接口 %s 到 netns %s 失败: %v", ifname, ns.name, err)
	}
	return nil
}

// Handle 返回命名空间句柄（用于需要直接操作的场景）
func (ns *NetNS) Handle() netns.NsHandle {
	return ns.handle
}

// Name 返回命名空间名称
func (ns *NetNS) Name() string {
	return ns.name
}
