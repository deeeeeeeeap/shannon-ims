package driver

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/iniwex5/netlink"
)

// XFRMManager 封装 Linux XFRM 子系统操作
// 使用 vishvananda/netlink 库管理 XFRM SA、SP 和 Interface
type XFRMManager struct {
	// undos 记录所有创建操作的回滚函数
	undos []func() error
}

// NewXFRMManager 创建 XFRM 管理器
func NewXFRMManager() *XFRMManager {
	return &XFRMManager{}
}

// FlushAll 清空所有 XFRM State 和 Policy（前置清理）
// 替代 exec.Command("ip", "xfrm", "state/policy", "flush")
func (x *XFRMManager) FlushAll() {
	_ = netlink.XfrmStateFlush(0) // proto=0 → 清空所有协议的 SA
	_ = netlink.XfrmPolicyFlush() // 清空所有 SP
}

// XFRMSAConfig XFRM Security Association 配置
type XFRMSAConfig struct {
	Src   net.IP // 本机 IP
	Dst   net.IP // 对端 IP (ePDG)
	SPI   uint32
	Proto netlink.Proto // 通常为 XFRM_PROTO_ESP

	// 算法配置 (AEAD 和 Crypt/Auth 互斥)
	IsAEAD bool

	// AEAD 模式 (如 AES-GCM)
	AeadAlgoName string
	AeadKey      []byte // encKey + salt
	AeadICVLen   int    // ICV 位数 (如 128)

	// 非 AEAD 模式 (如 AES-CBC + HMAC)
	CryptAlgoName string
	CryptKey      []byte
	AuthAlgoName  string
	AuthKey       []byte
	AuthTruncLen  int // 截断位数 (如 128)

	// ESP-in-UDP 封装 (NAT-T)
	EncapType    netlink.EncapType // XFRM_ENCAP_ESPINUDP
	EncapSrcPort int
	EncapDstPort int

	// XFRM Interface 关联
	Ifid int

	// Tunnel 模式 (VoWiFi 使用 tunnel 模式)
	Mode netlink.Mode // XFRM_MODE_TUNNEL

	// SA 生命周期（秒），用于触发内核 XFRM_MSG_EXPIRE 事件
	// Soft: 触发 rekey（默认 3300s = 55分钟）
	// Hard: 强制删除（默认 3600s = 60分钟）
	TimeLimitSoft uint64
	TimeLimitHard uint64

	// 抗重放窗口大小（0 = 使用默认值 32）
	ReplayWindow int

	// SA 方向标记（Linux 6.x+, XFRMA_SA_DIR）
	// 0 = 不设置, netlink.XFRM_SA_DIR_IN = 入站, netlink.XFRM_SA_DIR_OUT = 出站
	SADir netlink.SADir

	// 扩展序列号（ESN, RFC 4303 §2.2.1）
	// 64 位序列号，防止高速网络下 32 位 SN 溢出
	ESN bool
}

// XFRMSPConfig XFRM Security Policy 配置
type XFRMSPConfig struct {
	Src *net.IPNet  // 源地址范围
	Dst *net.IPNet  // 目标地址范围
	Dir netlink.Dir // XFRM_DIR_IN / XFRM_DIR_OUT / XFRM_DIR_FWD

	// 模板参数
	TmplSrc   net.IP
	TmplDst   net.IP
	TmplProto netlink.Proto
	TmplMode  netlink.Mode
	TmplSPI   int

	// XFRM Interface 关联
	Ifid int
}

// AddXFRMInterface 创建 XFRM 接口 (Linux 4.19+)
// name: 接口名 (如 "ipsec0")
// ifID: XFRM interface ID (用于关联 SA/SP)
// underlyingIdx: 底层物理接口的 link index (可设为 0 表示不指定)
func (x *XFRMManager) AddXFRMInterface(name string, ifID uint32, underlyingIdx int) error {
	// 尝试删除同名残留接口
	if existing, _ := netlink.LinkByName(name); existing != nil {
		_ = netlink.LinkDel(existing)
	}

	xfrmi := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
		Ifid: ifID,
	}
	if underlyingIdx > 0 {
		xfrmi.LinkAttrs.ParentIndex = underlyingIdx
	}

	if err := netlink.LinkAdd(xfrmi); err != nil {
		return fmt.Errorf("创建 XFRM 接口 %s 失败: %v", name, err)
	}

	// 禁用 ARP/ND (XFRMI 接口是 P2P 性质，不需要邻居解析)
	// 如果不禁用，内核可能会尝试对路由下一跳进行 ARP/ND 解析，导致 EHOSTUNREACH
	// StrongSwan 似乎不禁用 ARP？尝试允许 ARP 看是否解决 connection refused
	// if out, err := exec.Command("ip", "link", "set", "dev", name, "arp", "off").CombinedOutput(); err != nil {
	// 	fmt.Printf("警告: 禁用 XFRM 接口 ARP 失败: %v, output: %s\n", err, string(out))
	// }

	x.undos = append(x.undos, func() error {
		return x.DelXFRMInterface(name)
	})

	return nil
}

// DelXFRMInterface 删除 XFRM 接口
func (x *XFRMManager) DelXFRMInterface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // 接口不存在，视为成功
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("删除 XFRM 接口 %s 失败: %v", name, err)
	}
	return nil
}

// AddSA 添加 XFRM Security Association
func (x *XFRMManager) AddSA(cfg XFRMSAConfig) error {
	replayWindow := cfg.ReplayWindow
	if replayWindow <= 0 {
		replayWindow = 32
	}
	state := &netlink.XfrmState{
		Src:          cfg.Src,
		Dst:          cfg.Dst,
		Proto:        cfg.Proto,
		Mode:         cfg.Mode,
		Spi:          int(cfg.SPI),
		ReplayWindow: replayWindow,
		Ifid:         cfg.Ifid,
		// 参考 strongswan kernel_netlink_ipsec.c:1857
		// tunnel mode SA 需要设置 XFRM_STATE_AF_UNSPEC，允许处理任意地址族的流量
		AFUnspec: cfg.Mode == netlink.XFRM_MODE_TUNNEL,
		ESN:      cfg.ESN,
		SADir:    cfg.SADir,
		Limits: netlink.XfrmStateLimits{
			TimeSoft: cfg.TimeLimitSoft,
			TimeHard: cfg.TimeLimitHard,
		},
	}

	// 配置算法
	if cfg.IsAEAD {
		state.Aead = &netlink.XfrmStateAlgo{
			Name:   cfg.AeadAlgoName,
			Key:    cfg.AeadKey,
			ICVLen: cfg.AeadICVLen,
		}
	} else {
		if cfg.CryptAlgoName != "" {
			state.Crypt = &netlink.XfrmStateAlgo{
				Name: cfg.CryptAlgoName,
				Key:  cfg.CryptKey,
			}
		}
		if cfg.AuthAlgoName != "" {
			state.Auth = &netlink.XfrmStateAlgo{
				Name:        cfg.AuthAlgoName,
				Key:         cfg.AuthKey,
				TruncateLen: cfg.AuthTruncLen,
			}
		}
	}

	// ESP-in-UDP 封装 (NAT-T)
	if cfg.EncapType != 0 {
		state.Encap = &netlink.XfrmStateEncap{
			Type:    cfg.EncapType,
			SrcPort: cfg.EncapSrcPort,
			DstPort: cfg.EncapDstPort,
		}
	}

	if err := netlink.XfrmStateAdd(state); err != nil {
		return fmt.Errorf("添加 XFRM SA (spi=0x%x src=%v dst=%v) 失败: %v",
			cfg.SPI, cfg.Src, cfg.Dst, err)
	}

	x.undos = append(x.undos, func() error {
		return x.DelSA(cfg.SPI, cfg.Src, cfg.Dst, cfg.Proto)
	})

	return nil
}

// DelSA 删除 XFRM SA（幂等：SA 不存在时静默返回 nil）
func (x *XFRMManager) DelSA(spi uint32, src, dst net.IP, proto netlink.Proto) error {
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: proto,
		Spi:   int(spi),
	}
	if err := netlink.XfrmStateDel(state); err != nil {
		// SA 不存在（Rekey 后旧 SA 已被替换删除）视为正常
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("删除 XFRM SA (spi=0x%x) 失败: %v", spi, err)
	}
	return nil
}

// FlushByIP 清理所有包含该 IP (作为 src 或 dst) 的 XFRM SA 记录。
// 这可以防止会话崩溃后新建立的隧道 UDP 端口发送时被遗留路由拦截 (operation not permitted)。
func (x *XFRMManager) FlushByIP(ip net.IP) {
	if ip == nil {
		return
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err == nil {
		for _, s := range states {
			if s.Src.Equal(ip) || s.Dst.Equal(ip) {
				_ = netlink.XfrmStateDel(&s)
			}
		}
	}
}

// GetSALastUsed 查询指定 SPI 的内核 XFRM State，返回其最后被使用的时间戳。
// 用于辅助重传或 DPD 等保活机制中的流量静默判定，如果未查询到或者从未启用则返回 0 时间。
func (x *XFRMManager) GetSALastUsed(spi uint32, src, dst net.IP, proto netlink.Proto) (uint64, error) {
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: proto,
		Spi:   int(spi),
	}

	s, err := netlink.XfrmStateGet(state)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return 0, nil
		}
		return 0, fmt.Errorf("读取 XFRM SA (spi=0x%x) 状态失败: %v", spi, err)
	}

	return s.Statistics.UseTime, nil
}

// AddSP 添加 XFRM Security Policy
func (x *XFRMManager) AddSP(cfg XFRMSPConfig) error {
	policy := &netlink.XfrmPolicy{
		Src:  cfg.Src,
		Dst:  cfg.Dst,
		Dir:  cfg.Dir,
		Ifid: cfg.Ifid,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src: func() net.IP {
					if ip4 := cfg.TmplSrc.To4(); ip4 != nil {
						return ip4
					}
					return cfg.TmplSrc
				}(),
				Dst: func() net.IP {
					if ip4 := cfg.TmplDst.To4(); ip4 != nil {
						return ip4
					}
					return cfg.TmplDst
				}(),
				Proto: cfg.TmplProto,
				Mode:  cfg.TmplMode,
				Spi:   cfg.TmplSPI,
			},
		},
	}

	// 使用 Update 语义 (XFRM_MSG_UPDPOLICY)，参考 strongswan kernel_netlink_ipsec.c:3057
	// 覆盖已存在的同名策略，避免残留策略导致 file exists 错误
	if err := netlink.XfrmPolicyUpdate(policy); err != nil {
		return fmt.Errorf("添加/更新 XFRM SP (dir=%s src=%v dst=%v) 失败: %v",
			cfg.Dir, cfg.Src, cfg.Dst, err)
	}

	x.undos = append(x.undos, func() error {
		return x.DelSP(cfg)
	})

	return nil
}

// DelSP 删除 XFRM Security Policy（幂等：不存在时静默返回 nil）
func (x *XFRMManager) DelSP(cfg XFRMSPConfig) error {
	policy := &netlink.XfrmPolicy{
		Src:  cfg.Src,
		Dst:  cfg.Dst,
		Dir:  cfg.Dir,
		Ifid: cfg.Ifid,
	}
	if err := netlink.XfrmPolicyDel(policy); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("删除 XFRM SP (dir=%s) 失败: %v", cfg.Dir, err)
	}
	return nil
}

// Cleanup 清理所有创建的 XFRM 资源 (逆序回滚)
func (x *XFRMManager) Cleanup() {
	for i := len(x.undos) - 1; i >= 0; i-- {
		_ = x.undos[i]()
	}
	x.undos = nil
}

// UndoFuncs 返回所有回滚函数（供 Session 集成到统一的 cleanup 机制）
func (x *XFRMManager) UndoFuncs() []func() error {
	return x.undos
}

// UpdateSA 更新现有的 XFRM SA (用于 MOBIKE 地址变更)
func (x *XFRMManager) UpdateSA(cfg XFRMSAConfig) error {
	state := x.buildXfrmState(cfg)
	if err := netlink.XfrmStateUpdate(state); err != nil {
		return fmt.Errorf("更新 XFRM State 失败: %v", err)
	}
	return nil
}

// UpdateSP 更新现有的 XFRM SP
func (x *XFRMManager) UpdateSP(cfg XFRMSPConfig) error {
	policy := x.buildXfrmPolicy(cfg)
	if err := netlink.XfrmPolicyUpdate(policy); err != nil {
		return fmt.Errorf("更新 XFRM Policy 失败: %v", err)
	}
	return nil
}

// buildXfrmState 根据配置构建 netlink.XfrmState 对象
func (x *XFRMManager) buildXfrmState(cfg XFRMSAConfig) *netlink.XfrmState {
	state := &netlink.XfrmState{
		Src:   cfg.Src,
		Dst:   cfg.Dst,
		Proto: cfg.Proto,
		Mode:  cfg.Mode,
		Spi:   int(cfg.SPI),
		Ifid:  cfg.Ifid,
	}

	// 算法配置
	if cfg.IsAEAD {
		state.Aead = &netlink.XfrmStateAlgo{
			Name:   cfg.AeadAlgoName,
			Key:    cfg.AeadKey,
			ICVLen: cfg.AeadICVLen,
		}
	} else {
		state.Auth = &netlink.XfrmStateAlgo{
			Name: cfg.AuthAlgoName,
			Key:  cfg.AuthKey,
		}
		state.Crypt = &netlink.XfrmStateAlgo{
			Name: cfg.CryptAlgoName,
			Key:  cfg.CryptKey,
		}
	}

	// 封装配置
	if cfg.EncapType != 0 {
		state.Encap = &netlink.XfrmStateEncap{
			Type:    cfg.EncapType,
			SrcPort: cfg.EncapSrcPort,
			DstPort: cfg.EncapDstPort,
		}
	}

	// 生命周期
	state.Limits.TimeHard = cfg.TimeLimitHard
	state.Limits.TimeSoft = cfg.TimeLimitSoft

	// Replay Window
	if cfg.ReplayWindow > 0 {
		state.ReplayWindow = cfg.ReplayWindow
	} else {
		state.ReplayWindow = 128 // Default (已从默认 32 拉升至抗乱序更强的 128)
	}

	// SA 方向标记（Linux 6.x+）
	if cfg.SADir != 0 {
		state.SADir = cfg.SADir
	}

	// 扩展序列号（ESN）
	state.ESN = cfg.ESN

	return state
}

// buildXfrmPolicy 根据配置构建 netlink.XfrmPolicy 对象
func (x *XFRMManager) buildXfrmPolicy(cfg XFRMSPConfig) *netlink.XfrmPolicy {
	policy := &netlink.XfrmPolicy{
		Src:  cfg.Src,
		Dst:  cfg.Dst,
		Dir:  cfg.Dir,
		Ifid: cfg.Ifid,
	}

	tmpl := netlink.XfrmPolicyTmpl{
		Src:   cfg.TmplSrc,
		Dst:   cfg.TmplDst,
		Proto: cfg.TmplProto,
		Mode:  cfg.TmplMode,
		Spi:   cfg.TmplSPI,
	}
	policy.Tmpls = []netlink.XfrmPolicyTmpl{tmpl}
	return policy
}
