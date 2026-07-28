package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// Milenage 实现 3GPP TS 35.206 规范的认证算法
// 用于 EAP-AKA 认证，支持软件 SIM (不需要物理 SIM 卡)
type Milenage struct {
	K   [16]byte // 128 位用户密钥
	OP  [16]byte // 128 位运营商变体算法配置字段
	OPc [16]byte // 派生的 OPc = AES_K(OP) ⊕ OP
}

// NewMilenage 创建 Milenage 实例
// k: 128 位用户密钥
// op: 128 位运营商密钥 (OP 或 OPc)
// useOPc: 如果为 true，则 op 参数是 OPc，否则是 OP
func NewMilenage(k, op []byte, useOPc bool) (*Milenage, error) {
	if len(k) != 16 || len(op) != 16 {
		return nil, errors.New("K 和 OP/OPc 必须是 16 字节")
	}

	m := &Milenage{}
	copy(m.K[:], k)
	copy(m.OP[:], op)

	if useOPc {
		// 直接使用 OPc
		copy(m.OPc[:], op)
	} else {
		// 计算 OPc = AES_K(OP) ⊕ OP
		m.computeOPc()
	}

	return m, nil
}

// computeOPc 计算 OPc = AES_K(OP) ⊕ OP
func (m *Milenage) computeOPc() {
	cipher, _ := aes.NewCipher(m.K[:])
	var encrypted [16]byte
	cipher.Encrypt(encrypted[:], m.OP[:])

	for i := 0; i < 16; i++ {
		m.OPc[i] = encrypted[i] ^ m.OP[i]
	}
}

// F1 计算网络认证码 MAC-A 和重同步认证码 MAC-S
// 输入: RAND (16字节), SQN (6字节), AMF (2字节)
// 输出: MAC-A (8字节), MAC-S (8字节)
func (m *Milenage) F1(rand, sqn, amf []byte) (macA, macS []byte, err error) {
	if len(rand) != 16 || len(sqn) != 6 || len(amf) != 2 {
		return nil, nil, errors.New("F1: 参数长度错误")
	}

	cipher, _ := aes.NewCipher(m.K[:])

	// TEMP = AES_K(RAND ⊕ OPc)
	var temp [16]byte
	for i := 0; i < 16; i++ {
		temp[i] = rand[i] ^ m.OPc[i]
	}
	cipher.Encrypt(temp[:], temp[:])

	// IN1 = SQN || AMF || SQN || AMF
	var in1 [16]byte
	copy(in1[0:6], sqn)
	copy(in1[6:8], amf)
	copy(in1[8:14], sqn)
	copy(in1[14:16], amf)

	// OUT1 = AES_K(rot(TEMP ⊕ OPc, r1) ⊕ c1 ⊕ IN1) ⊕ OPc
	// r1 = 64, c1 = 0x00...00
	var tmp [16]byte
	for i := 0; i < 16; i++ {
		tmp[i] = temp[i] ^ m.OPc[i]
	}
	tmp = rotate(tmp, 64)
	for i := 0; i < 16; i++ {
		tmp[i] ^= in1[i]
	}
	cipher.Encrypt(tmp[:], tmp[:])
	for i := 0; i < 16; i++ {
		tmp[i] ^= m.OPc[i]
	}

	// MAC-A = OUT1[0:8], MAC-S = OUT1[8:16]
	macA = make([]byte, 8)
	macS = make([]byte, 8)
	copy(macA, tmp[0:8])
	copy(macS, tmp[8:16])

	return macA, macS, nil
}

// F2F5 计算响应 RES 和匿名密钥 AK
// 输入: RAND (16字节)
// 输出: RES (8字节), AK (6字节)
func (m *Milenage) F2F5(rand []byte) (res, ak []byte, err error) {
	if len(rand) != 16 {
		return nil, nil, errors.New("F2F5: RAND 必须是 16 字节")
	}

	cipher, _ := aes.NewCipher(m.K[:])

	// TEMP = AES_K(RAND ⊕ OPc)
	var temp [16]byte
	for i := 0; i < 16; i++ {
		temp[i] = rand[i] ^ m.OPc[i]
	}
	cipher.Encrypt(temp[:], temp[:])

	// OUT2 = AES_K(rot(TEMP ⊕ OPc, r2) ⊕ c2) ⊕ OPc
	// r2 = 0, c2 = 0x00...01
	var tmp [16]byte
	for i := 0; i < 16; i++ {
		tmp[i] = temp[i] ^ m.OPc[i]
	}
	// c2 = 0x00...01
	tmp[15] ^= 1
	cipher.Encrypt(tmp[:], tmp[:])
	for i := 0; i < 16; i++ {
		tmp[i] ^= m.OPc[i]
	}

	// RES = OUT2[8:16], AK = OUT2[0:6]
	res = make([]byte, 8)
	ak = make([]byte, 6)
	copy(res, tmp[8:16])
	copy(ak, tmp[0:6])

	return res, ak, nil
}

// F3 计算加密密钥 CK
// 输入: RAND (16字节)
// 输出: CK (16字节)
func (m *Milenage) F3(rand []byte) (ck []byte, err error) {
	if len(rand) != 16 {
		return nil, errors.New("F3: RAND 必须是 16 字节")
	}

	cipher, _ := aes.NewCipher(m.K[:])

	// TEMP = AES_K(RAND ⊕ OPc)
	var temp [16]byte
	for i := 0; i < 16; i++ {
		temp[i] = rand[i] ^ m.OPc[i]
	}
	cipher.Encrypt(temp[:], temp[:])

	// OUT3 = AES_K(rot(TEMP ⊕ OPc, r3) ⊕ c3) ⊕ OPc
	// r3 = 32, c3 = 0x00...02
	var tmp [16]byte
	for i := 0; i < 16; i++ {
		tmp[i] = temp[i] ^ m.OPc[i]
	}
	tmp = rotate(tmp, 32)
	tmp[15] ^= 2
	cipher.Encrypt(tmp[:], tmp[:])
	for i := 0; i < 16; i++ {
		tmp[i] ^= m.OPc[i]
	}

	ck = make([]byte, 16)
	copy(ck, tmp[:])
	return ck, nil
}

// F4 计算完整性密钥 IK
// 输入: RAND (16字节)
// 输出: IK (16字节)
func (m *Milenage) F4(rand []byte) (ik []byte, err error) {
	if len(rand) != 16 {
		return nil, errors.New("F4: RAND 必须是 16 字节")
	}

	cipher, _ := aes.NewCipher(m.K[:])

	// TEMP = AES_K(RAND ⊕ OPc)
	var temp [16]byte
	for i := 0; i < 16; i++ {
		temp[i] = rand[i] ^ m.OPc[i]
	}
	cipher.Encrypt(temp[:], temp[:])

	// OUT4 = AES_K(rot(TEMP ⊕ OPc, r4) ⊕ c4) ⊕ OPc
	// r4 = 64, c4 = 0x00...04
	var tmp [16]byte
	for i := 0; i < 16; i++ {
		tmp[i] = temp[i] ^ m.OPc[i]
	}
	tmp = rotate(tmp, 64)
	tmp[15] ^= 4
	cipher.Encrypt(tmp[:], tmp[:])
	for i := 0; i < 16; i++ {
		tmp[i] ^= m.OPc[i]
	}

	ik = make([]byte, 16)
	copy(ik, tmp[:])
	return ik, nil
}

// F5Star 计算重同步用的匿名密钥 AK*
// 输入: RAND (16字节)
// 输出: AK* (6字节)
func (m *Milenage) F5Star(rand []byte) (akStar []byte, err error) {
	if len(rand) != 16 {
		return nil, errors.New("F5Star: RAND 必须是 16 字节")
	}

	cipher, _ := aes.NewCipher(m.K[:])

	// TEMP = AES_K(RAND ⊕ OPc)
	var temp [16]byte
	for i := 0; i < 16; i++ {
		temp[i] = rand[i] ^ m.OPc[i]
	}
	cipher.Encrypt(temp[:], temp[:])

	// OUT5 = AES_K(rot(TEMP ⊕ OPc, r5) ⊕ c5) ⊕ OPc
	// r5 = 96, c5 = 0x00...08
	var tmp [16]byte
	for i := 0; i < 16; i++ {
		tmp[i] = temp[i] ^ m.OPc[i]
	}
	tmp = rotate(tmp, 96)
	tmp[15] ^= 8
	cipher.Encrypt(tmp[:], tmp[:])
	for i := 0; i < 16; i++ {
		tmp[i] ^= m.OPc[i]
	}

	akStar = make([]byte, 6)
	copy(akStar, tmp[0:6])
	return akStar, nil
}

// GenerateAUTN 生成认证令牌 AUTN
// AUTN = (SQN ⊕ AK) || AMF || MAC-A
func (m *Milenage) GenerateAUTN(rand, sqn, amf []byte) (autn []byte, err error) {
	_, ak, err := m.F2F5(rand)
	if err != nil {
		return nil, err
	}

	macA, _, err := m.F1(rand, sqn, amf)
	if err != nil {
		return nil, err
	}

	autn = make([]byte, 16)
	// SQN ⊕ AK
	for i := 0; i < 6; i++ {
		autn[i] = sqn[i] ^ ak[i]
	}
	// AMF
	copy(autn[6:8], amf)
	// MAC-A
	copy(autn[8:16], macA)

	return autn, nil
}

// VerifyAUTN 验证 AUTN 并返回 RES, CK, IK
// 如果验证失败返回 AUTS (用于重同步)
func (m *Milenage) VerifyAUTN(rand, autn []byte, expectedSQN uint64) (res, ck, ik, auts []byte, err error) {
	if len(rand) != 16 || len(autn) != 16 {
		return nil, nil, nil, nil, errors.New("VerifyAUTN: 参数长度错误")
	}

	// 提取 AK
	resVal, ak, err := m.F2F5(rand)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 从 AUTN 恢复 SQN
	sqn := make([]byte, 6)
	for i := 0; i < 6; i++ {
		sqn[i] = autn[i] ^ ak[i]
	}
	amf := autn[6:8]
	receivedMAC := autn[8:16]

	// 验证 MAC-A
	macA, _, err := m.F1(rand, sqn, amf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// 比较 MAC
	for i := 0; i < 8; i++ {
		if macA[i] != receivedMAC[i] {
			return nil, nil, nil, nil, errors.New("MAC 验证失败")
		}
	}

	// 验证 SQN (简化版本)
	receivedSQN := decodeSQN(sqn)
	if receivedSQN < expectedSQN {
		// SQN 不同步，生成 AUTS
		auts, err = m.GenerateAUTS(rand, sqn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return nil, nil, nil, auts, errors.New("SQN 不同步")
	}

	// 计算 CK 和 IK
	ck, err = m.F3(rand)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ik, err = m.F4(rand)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return resVal, ck, ik, nil, nil
}

// GenerateAUTS 生成重同步参数
// AUTS = (SQN ⊕ AK*) || MAC-S
func (m *Milenage) GenerateAUTS(rand, sqn []byte) ([]byte, error) {
	akStar, err := m.F5Star(rand)
	if err != nil {
		return nil, err
	}

	// AMF 在重同步中使用固定值
	amfResync := []byte{0x00, 0x00}
	_, macS, err := m.F1(rand, sqn, amfResync)
	if err != nil {
		return nil, err
	}

	auts := make([]byte, 14)
	for i := 0; i < 6; i++ {
		auts[i] = sqn[i] ^ akStar[i]
	}
	copy(auts[6:14], macS)

	return auts, nil
}

// rotate 循环左移 bits 位
func rotate(data [16]byte, bits int) [16]byte {
	var result [16]byte
	byteShift := bits / 8
	for i := 0; i < 16; i++ {
		result[i] = data[(i+byteShift)%16]
	}
	return result
}

// decodeSQN 从 6 字节解码 SQN
func decodeSQN(data []byte) uint64 {
	if len(data) < 6 {
		return 0
	}
	return uint64(data[0])<<40 | uint64(data[1])<<32 |
		uint64(data[2])<<24 | uint64(data[3])<<16 |
		uint64(data[4])<<8 | uint64(data[5])
}

// EncodeSQN 将 SQN 编码为 6 字节
func EncodeSQN(sqn uint64) []byte {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], uint16(sqn>>32))
	binary.BigEndian.PutUint32(buf[2:6], uint32(sqn))
	return buf
}
