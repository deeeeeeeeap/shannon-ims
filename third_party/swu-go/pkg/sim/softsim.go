package sim

import (
	"github.com/1239t/swu-go/pkg/crypto"
)

// SoftSIM 软件 SIM 实现 (使用 Milenage 算法)
// 不需要物理 SIM 卡，用于测试或特殊场景
type SoftSIM struct {
	IMSI     string
	milenage *crypto.Milenage
	SQN      uint64 // 当前序列号
}

// NewSoftSIM 创建软件 SIM
// k: 128 位用户密钥 (Ki)
// op: 128 位运营商密钥 (OP 或 OPc)
// useOPc: 如果为 true，使用 OPc；否则使用 OP
func NewSoftSIM(imsi string, k, op []byte, useOPc bool) (*SoftSIM, error) {
	m, err := crypto.NewMilenage(k, op, useOPc)
	if err != nil {
		return nil, err
	}

	return &SoftSIM{
		IMSI:     imsi,
		milenage: m,
		SQN:      0,
	}, nil
}

// GetIMSI 返回 IMSI
func (s *SoftSIM) GetIMSI() (string, error) {
	return s.IMSI, nil
}

// CalculateAKA 执行 AKA 认证
// 返回: RES, CK, IK, AUTS (如果 SQN 不同步)
func (s *SoftSIM) CalculateAKA(rand, autn []byte) (res, ck, ik, auts []byte, err error) {
	res, ck, ik, auts, err = s.milenage.VerifyAUTN(rand, autn, s.SQN)
	if err != nil {
		if auts != nil {
			// SQN 不同步，返回 AUTS
			return nil, nil, nil, auts, err
		}
		return nil, nil, nil, nil, err
	}

	// 更新 SQN
	// 从 AUTN 中提取并更新
	_, ak, _ := s.milenage.F2F5(rand)
	sqn := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqn[i] = autn[i] ^ ak[i]
	}
	s.SQN = decodeSQN(sqn) + 1

	return res, ck, ik, nil, nil
}

// Close 关闭 (无操作)
func (s *SoftSIM) Close() error {
	return nil
}

// SetSQN 设置初始 SQN
func (s *SoftSIM) SetSQN(sqn uint64) {
	s.SQN = sqn
}

// GetSQN 获取当前 SQN
func (s *SoftSIM) GetSQN() uint64 {
	return s.SQN
}

func decodeSQN(data []byte) uint64 {
	if len(data) < 6 {
		return 0
	}
	return uint64(data[0])<<40 | uint64(data[1])<<32 |
		uint64(data[2])<<24 | uint64(data[3])<<16 |
		uint64(data[4])<<8 | uint64(data[5])
}
