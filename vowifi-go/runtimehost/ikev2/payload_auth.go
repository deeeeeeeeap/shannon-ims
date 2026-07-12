package ikev2

import (
	"errors"
)

// 认证载荷 (RFC 7296 3.8 节)
type EncryptedPayloadAuth struct {
	AuthMethod uint8
	AuthData   []byte
}

const (
	AuthMethodRSASig    = 1
	AuthMethodSharedKey = 2
	AuthMethodDSSSig    = 3
)

func (p *EncryptedPayloadAuth) Type() PayloadType { return AUTH }

func (p *EncryptedPayloadAuth) Encode() ([]byte, error) {
	// 头部: 1 字节认证方法 + 3 字节保留 + 数据
	buf := make([]byte, 4+len(p.AuthData))
	buf[0] = p.AuthMethod
	// buf[1:4] 保留 = 0
	copy(buf[4:], p.AuthData)
	return buf, nil
}

func DecodePayloadAuth(data []byte) (*EncryptedPayloadAuth, error) {
	if len(data) < 4 {
		return nil, errors.New("认证载荷太短")
	}
	return &EncryptedPayloadAuth{
		AuthMethod: data[0],
		AuthData:   data[4:],
	}, nil
}
