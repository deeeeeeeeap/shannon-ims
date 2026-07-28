package swu

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"

	"github.com/1239t/swu-go/pkg/crypto"
	"github.com/1239t/swu-go/pkg/ikev2"
)

// GenerateIKESAKeys 根据 RFC 7296 2.13 和 2.14 生成密钥
func (s *Session) GenerateIKESAKeys(peerNonce []byte) error {
	// 1. 计算 SKEYSEED = prf(Ni | Nr, g^ir)
	if s.DH.SharedKey == nil {
		return errors.New("DH 共享密钥未计算")
	}

	seed := append(s.ni, peerNonce...)

	prf := s.PRFAlg
	mac := hmac.New(prf.Hash, seed)
	mac.Write(s.DH.SharedKey)
	skeyseed := mac.Sum(nil)

	// 2. 计算密钥
	totalLen := 0
	prfKeyLen := prf.KeyLen()

	encKeyLen := 0
	if s.EncAlg == nil {
		return errors.New("IKE 加密算法未设置")
	}
	if s.ikeIsAEAD {
		encKeyLen = s.EncAlg.KeySize() + 4
	} else {
		encKeyLen = s.EncAlg.KeySize()
	}

	integKeyLen := 0
	if !s.ikeIsAEAD {
		if s.IntegAlg == nil {
			return errors.New("IKE 完整性算法未设置")
		}
		integKeyLen = s.IntegAlg.KeySize()
	}

	totalLen += prfKeyLen * 3   // SK_d, SK_pi, SK_pr
	totalLen += integKeyLen * 2 // SK_ai, SK_ar
	totalLen += encKeyLen * 2   // SK_ei, SK_er

	input := append(s.ni, peerNonce...)
	spiBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(spiBytes[0:8], s.SPIi)
	binary.BigEndian.PutUint64(spiBytes[8:16], s.SPIr)
	input = append(input, spiBytes...)

	keyMat, err := crypto.PrfPlus(prf, skeyseed, input, totalLen)
	if err != nil {
		return err
	}

	s.Keys = &ikev2.IKESAKeys{}
	cursor := 0

	s.Keys.SK_d = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen

	if integKeyLen > 0 {
		s.Keys.SK_ai = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
		s.Keys.SK_ar = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}

	s.Keys.SK_ei = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen
	s.Keys.SK_er = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen

	s.Keys.SK_pi = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen
	s.Keys.SK_pr = keyMat[cursor : cursor+prfKeyLen]

	return nil
}

// GenerateIKESARekeyKeys 根据 RFC 7296 §2.18 生成 IKE SA Rekey 的新密钥
// 与初始 SA 区别：SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
// 参考 strongSwan keymat_v2.c:362
func (s *Session) GenerateIKESARekeyKeys(
	oldSKd []byte, newDHSecret []byte,
	ni, nr []byte, newSPIi, newSPIr uint64,
) (*ikev2.IKESAKeys, error) {
	if len(oldSKd) == 0 {
		return nil, errors.New("旧 SK_d 为空")
	}
	if len(newDHSecret) == 0 {
		return nil, errors.New("新 DH 共享密钥为空")
	}

	prf := s.PRFAlg

	// 1. SKEYSEED = prf(SK_d_old, g^ir_new | Ni | Nr)
	// key = SK_d_old, data = DHSecret | Ni | Nr
	data := make([]byte, 0, len(newDHSecret)+len(ni)+len(nr))
	data = append(data, newDHSecret...)
	data = append(data, ni...)
	data = append(data, nr...)

	mac := hmac.New(prf.Hash, oldSKd)
	mac.Write(data)
	skeyseed := mac.Sum(nil)

	// 2. 计算密钥材料长度
	prfKeyLen := prf.KeyLen()

	encKeyLen := 0
	if s.EncAlg == nil {
		return nil, errors.New("IKE 加密算法未设置")
	}
	if s.ikeIsAEAD {
		encKeyLen = s.EncAlg.KeySize() + 4
	} else {
		encKeyLen = s.EncAlg.KeySize()
	}

	integKeyLen := 0
	if !s.ikeIsAEAD {
		if s.IntegAlg == nil {
			return nil, errors.New("IKE 完整性算法未设置")
		}
		integKeyLen = s.IntegAlg.KeySize()
	}

	totalLen := prfKeyLen*3 + integKeyLen*2 + encKeyLen*2

	// 3. KEYMAT = prf+(SKEYSEED, Ni | Nr | new_SPIi | new_SPIr)
	input := make([]byte, 0, len(ni)+len(nr)+16)
	input = append(input, ni...)
	input = append(input, nr...)
	spiBytes := make([]byte, 16)
	binary.BigEndian.PutUint64(spiBytes[0:8], newSPIi)
	binary.BigEndian.PutUint64(spiBytes[8:16], newSPIr)
	input = append(input, spiBytes...)

	keyMat, err := crypto.PrfPlus(prf, skeyseed, input, totalLen)
	if err != nil {
		return nil, err
	}

	// 4. 切分密钥：SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
	keys := &ikev2.IKESAKeys{}
	cursor := 0

	keys.SK_d = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen

	if integKeyLen > 0 {
		keys.SK_ai = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
		keys.SK_ar = keyMat[cursor : cursor+integKeyLen]
		cursor += integKeyLen
	}

	keys.SK_ei = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen
	keys.SK_er = keyMat[cursor : cursor+encKeyLen]
	cursor += encKeyLen

	keys.SK_pi = keyMat[cursor : cursor+prfKeyLen]
	cursor += prfKeyLen
	keys.SK_pr = keyMat[cursor : cursor+prfKeyLen]

	return keys, nil
}
