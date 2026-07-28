package crypto

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// RFC 3526 模指数 (MODP) Diffie-Hellman 组

var (
	// 组 14: 2048 位 MODP 组
	// 素数是 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
	prime2048, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	prime3072, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
	gen2         = big.NewInt(2)
)

type DiffieHellman struct {
	Group      uint16
	PrivateKey *big.Int
	PublicKey  *big.Int
	SharedKey  []byte
	P          *big.Int
	G          *big.Int
}

func NewDiffieHellman(group uint16) (*DiffieHellman, error) {
	dh := &DiffieHellman{Group: group}

	switch group {
	case 14: // MODP 2048
		dh.P = prime2048
		dh.G = gen2
	case 15: // MODP 3072
		dh.P = prime3072
		dh.G = gen2
	default:
		return nil, errors.New("不支持的 DH 组")
	}

	return dh, nil
}

func (dh *DiffieHellman) GenerateKey() error {
	// 生成私钥: 随机数 < P
	// 等等，RFC 建议私钥长度 >= 2 * 组强度。
	// 对于 2048 (112 位强度)，224 位就足够了。
	// 但通常我们使用更大的。为简单起见，让我们使用 2048 位或稍微小一点。
	// 通常严格要求是 [1, P-1]。

	privateRange := new(big.Int).Sub(dh.P, big.NewInt(3))
	privateKey, err := rand.Int(rand.Reader, privateRange)
	if err != nil {
		return err
	}
	dh.PrivateKey = privateKey.Add(privateKey, big.NewInt(2))

	// 计算公钥: G^x mod P
	dh.PublicKey = new(big.Int).Exp(dh.G, dh.PrivateKey, dh.P)

	return nil
}

func (dh *DiffieHellman) ComputeSharedSecret(peerPubKeyBytes []byte) ([]byte, error) {
	keyLen := (dh.P.BitLen() + 7) / 8
	if len(peerPubKeyBytes) != keyLen {
		return nil, errors.New("无效的对端公钥长度")
	}
	peerPubKey := new(big.Int).SetBytes(peerPubKeyBytes)

	// 验证对端密钥: 1 < peer < P-1
	one := big.NewInt(1)
	pMinusOne := new(big.Int).Sub(dh.P, one)
	if peerPubKey.Cmp(one) <= 0 || peerPubKey.Cmp(pMinusOne) >= 0 {
		return nil, errors.New("无效的对端公钥")
	}

	// 计算 S = peer^x mod P
	secret := new(big.Int).Exp(peerPubKey, dh.PrivateKey, dh.P)

	// 转换为字节 (左侧填充零以匹配载荷长度)
	// P 是 2048 位 (256 字节)
	secretBytes := secret.Bytes()

	if len(secretBytes) < keyLen {
		padding := make([]byte, keyLen-len(secretBytes))
		dh.SharedKey = append(padding, secretBytes...)
	} else {
		dh.SharedKey = secretBytes
	}

	return dh.SharedKey, nil
}

func (dh *DiffieHellman) PublicKeyBytes() []byte {
	// P 是 2048 位 (256 字节)
	keyLen := (dh.P.BitLen() + 7) / 8
	pubBytes := dh.PublicKey.Bytes()

	if len(pubBytes) < keyLen {
		padding := make([]byte, keyLen-len(pubBytes))
		return append(padding, pubBytes...)
	}
	return pubBytes
}
