package ikev2

// IKE SA 密钥材料 (RFC 7296 2.13 和 2.14 节)
type IKESAKeys struct {
	SK_d  []byte // 用于派生新密钥的密钥 (用于 Child SA 等)
	SK_ai []byte // 发起方完整性密钥
	SK_ar []byte // 响应方完整性密钥
	SK_ei []byte // 发起方加密密钥
	SK_er []byte // 响应方加密密钥
	SK_pi []byte // 发起方认证载荷密钥
	SK_pr []byte // 响应方认证载荷密钥
}

// Child SA 密钥材料 (RFC 7296 2.17 节)
type ChildSAKeys struct {
	SK_ei []byte // 发起方加密密钥
	SK_ai []byte // 发起方完整性密钥
	SK_er []byte // 响应方加密密钥
	SK_ar []byte // 响应方完整性密钥
}
