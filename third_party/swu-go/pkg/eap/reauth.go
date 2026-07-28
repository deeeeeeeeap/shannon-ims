package eap

// 快速重认证状态
type ReauthState struct {
	NextReauthID string // 下一次重认证 ID (从服务器获取)
	Counter      uint16 // 重认证计数器
	MK           []byte // 主密钥 (来自完整认证)
	KEncr        []byte // 加密密钥
	KAut         []byte // 认证密钥
	MSK          []byte // 主会话密钥
	EMSK         []byte // 扩展主会话密钥
}

// FastReauthContext 快速重认证上下文
type FastReauthContext struct {
	Enabled      bool
	ReauthID     string // 当前重认证 ID
	Counter      uint16
	NonceS       []byte // 服务器 Nonce
	CounterSmall bool   // AT_COUNTER_TOO_SMALL 标志

	// 保存的密钥
	KEncr []byte
	KAut  []byte
	MK    []byte
}

// NewFastReauthContext 创建快速重认证上下文
func NewFastReauthContext() *FastReauthContext {
	return &FastReauthContext{
		Enabled: false,
	}
}

// SaveReauthData 保存重认证数据 (从 AT_NEXT_REAUTH_ID 获取)
func (ctx *FastReauthContext) SaveReauthData(nextReauthID string, mk, kEncr, kAut []byte) {
	ctx.ReauthID = nextReauthID
	ctx.MK = mk
	ctx.KEncr = kEncr
	ctx.KAut = kAut
	ctx.Enabled = true
	ctx.Counter = 0
}

// CanUseReauth 检查是否可以使用快速重认证
func (ctx *FastReauthContext) CanUseReauth() bool {
	return ctx.Enabled && ctx.ReauthID != ""
}

// BuildReauthResponse 构建重认证响应
// AT_COUNTER + AT_COUNTER_TOO_SMALL (如果需要) + AT_MAC
func (ctx *FastReauthContext) BuildReauthResponse(nonceS []byte, counter uint16) ([]byte, error) {
	ctx.NonceS = nonceS
	ctx.Counter = counter

	// 验证计数器
	// 如果服务器计数器太小，设置 CounterSmall 标志
	// 这需要完整重新认证

	response := []byte{}

	// AT_COUNTER (固定 4 字节)
	response = append(response, AT_COUNTER, 1) // Type=19, Length=1 (4 bytes)
	response = append(response, byte(counter>>8), byte(counter))

	// AT_MAC 需要在最后计算
	// 预留 20 字节 (Type + Length + Reserved + 16字节 MAC)
	macOffset := len(response)
	response = append(response, AT_MAC, 5, 0, 0) // Type=11, Length=5
	response = append(response, make([]byte, 16)...)

	// 计算 MAC (使用 K_aut)
	// MAC 覆盖整个 EAP 消息
	// 这里只是占位，实际 MAC 需要在完整消息构建后计算
	_ = macOffset

	return response, nil
}

// 注意: AT_COUNTER, AT_COUNTER_TOO_SMALL, AT_NONCE_S, AT_NEXT_REAUTH_ID
// 已在 packet.go 中定义
