package sim

import "errors"

// SIMProvider 定义了获取 SIM 卡信息和执行 AKA 鉴权的接口
type SIMProvider interface {
	// 获取 IMSI (International Mobile Subscriber Identity)
	GetIMSI() (string, error)

	// 执行 AKA 鉴权
	// rand: 16 bytes 随机数
	// autn: 16 bytes 认证令牌
	// 返回: res (Response), ck (Cipher Key), ik (Integrity Key), auts (Sync Failure Token), err
	CalculateAKA(rand []byte, autn []byte) (res, ck, ik, auts []byte, err error)

	// 关闭资源 (如串口)
	Close() error
}

type IMEIProvider interface {
	GetIMEI() (string, error)
}

var (
	ErrSIMNotPresent = errors.New("SIM card not present")
	ErrAuthFailed    = errors.New("authentication failed")
	ErrSyncFailure   = errors.New("synchronization failure")
)
