package swu

import (
	"github.com/1239t/swu-go/pkg/sim"
)

type Config struct {
	EpDGAddr  string
	EpDGPort  uint16 // 默认 500
	APN       string
	LocalAddr string // 传出接口 IP (通常自动检测)
	DNSServer string // 可选: 用于解析 ePDG 域名的 DNS 服务器 (host:port)

	SIM          sim.SIMProvider
	EnableDriver bool // 是否创建 TUN 和路由 (需要 root)

	// 数据平面模式: "tun" (默认，用户空间 ESP) 或 "xfrmi" (内核 XFRM offload)
	DataplaneMode string
	// XFRMI 模式专用配置
	XFRMIfID uint32 // XFRM interface ID (默认自动分配)

	// 可选的特定配置
	MCC       string
	MNC       string
	LocalPort uint16 // 本地 UDP 端口 (默认 500)
	// IKE SA 重认证间隔（秒），0 表示禁用
	// 默认 0 (不主动重认证，仅 Rekey)
	ReauthInterval int

	TUNName string // TUN 设备名 (默认自动分配)
	TUNMTU  int    // TUN MTU，0 表示使用默认值（默认 1358，已预留约 142B 的 ESP-in-UDP 封装开销）

	// XFRM SA 抗重放窗口大小（0 = 使用默认值 32）
	// 高延迟/乱序网络建议设为 128 或 256
	ReplayWindow int

	// 启用 ESN（Extended Sequence Numbers, RFC 4303 §2.2.1）
	// 64 位序列号，防止高速网络下 32 位 SN 溢出
	// 默认 false（VoWiFi 场景通常不需要）
	EnableESN bool

	DisableEAPMACValidation bool

	EnableWiresharkKeyLog bool
	WiresharkKeyLogPath   string

	// RFC 5723: Session Resumption 跨会话凭证漂流保护
	ResumeTicket   []byte
	ResumeOldSKd   []byte
	OnTicketUpdate func(ticket, skd []byte)

	// RFC 4187: EAP-AKA Fast Re-authentication 跨会话快速重连
	// 从 ePDG 鉴权成功后提取的假名 ID 和密钥材料，用于下次断线重连时
	// 绕过物理 SIM 卡读取（AT+CSIM），实现 0-RTT 的极速软鉴权
	FastReauthID       string                                        // 来自 AT_NEXT_REAUTH_ID 的临时假名
	FastReauthMK       []byte                                        // Master Key (上次全量认证派生)
	FastReauthKAut     []byte                                        // K_Aut (用于 MAC 校验)
	FastReauthKEncr    []byte                                        // K_Encr (用于属性加密)
	OnFastReauthUpdate func(reauthID string, mk, kAut, kEncr []byte) // 外层持久化回调

	TransportFactory func(local string, remote string) (Transport, error)
	TUNFactory       func(name string) (TUN, error)
	NetTools         NetTools

	// OnReady is invoked once the Child SA dataplane is ready for inner traffic.
	OnReady func()

	// 支持自定义的 IKEv2 和 ESP 协商组合列表。如果留空，将使用内置的大而全强兼容默认套件。
	// 示例：[]string{"aes256gcm16-prfsha384-ecp384", "aes128-sha256-modp2048"}
	IKEProposals []string
	ESPProposals []string
}
