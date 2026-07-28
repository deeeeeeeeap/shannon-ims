package crypto

import (
	"bytes"
	cryptorand "crypto/rand"
	"math/big"
	"strings"
	"testing"
)

const rfc3526Group15PrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DDE" +
	"F9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
	"DE2BCBF6955817183995497CEA956AE515D2261898FA051015" +
	"728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64EC" +
	"FB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7AB" +
	"F5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF1" +
	"2FFA06D98A0864D87602733EC86A64521F2B18177B200CBB" +
	"E117577A615D6C770988C0BAD946E208E24FA074E5AB3143" +
	"DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

func TestNewDiffieHellmanGroup15UsesRFC3526Parameters(t *testing.T) {
	dh, err := NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("NewDiffieHellman(15) failed: %v", err)
	}
	if dh.Group != 15 {
		t.Fatalf("group = %d, want 15", dh.Group)
	}
	if dh.P.BitLen() != 3072 {
		t.Fatalf("prime bit length = %d, want 3072", dh.P.BitLen())
	}
	if strings.ToUpper(dh.P.Text(16)) != rfc3526Group15PrimeHex {
		t.Fatal("group 15 prime does not match RFC 3526")
	}
	if dh.G.Cmp(big.NewInt(2)) != 0 {
		t.Fatal("group 15 generator is not 2")
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	if len(dh.PublicKeyBytes()) != 384 {
		t.Fatalf("public key length = %d, want 384", len(dh.PublicKeyBytes()))
	}
}

func TestDiffieHellmanGenerateKeyUsesPrivateExponentRange(t *testing.T) {
	originalReader := cryptorand.Reader
	cryptorand.Reader = bytes.NewReader(make([]byte, 512))
	t.Cleanup(func() { cryptorand.Reader = originalReader })

	dh, err := NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("NewDiffieHellman(15) failed: %v", err)
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	minimum := big.NewInt(2)
	maximum := new(big.Int).Sub(dh.P, minimum)
	if dh.PrivateKey.Cmp(minimum) < 0 || dh.PrivateKey.Cmp(maximum) > 0 {
		t.Fatal("private exponent is outside [2, P-2]")
	}
}

func TestDiffieHellmanGroup15DerivesFixedWidthSharedSecret(t *testing.T) {
	alice, err := NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create Alice DH: %v", err)
	}
	bob, err := NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("create Bob DH: %v", err)
	}
	if err := alice.GenerateKey(); err != nil {
		t.Fatalf("generate Alice key: %v", err)
	}
	if err := bob.GenerateKey(); err != nil {
		t.Fatalf("generate Bob key: %v", err)
	}
	aliceSecret, err := alice.ComputeSharedSecret(bob.PublicKeyBytes())
	if err != nil {
		t.Fatalf("derive Alice secret: %v", err)
	}
	bobSecret, err := bob.ComputeSharedSecret(alice.PublicKeyBytes())
	if err != nil {
		t.Fatalf("derive Bob secret: %v", err)
	}
	if len(aliceSecret) != 384 || len(bobSecret) != 384 {
		t.Fatalf("shared secret lengths = %d/%d, want 384/384", len(aliceSecret), len(bobSecret))
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatal("group 15 peers derived different shared secrets")
	}
}

func TestDiffieHellmanGroup15RejectsInvalidPeerKeys(t *testing.T) {
	dh, err := NewDiffieHellman(15)
	if err != nil {
		t.Fatalf("NewDiffieHellman(15) failed: %v", err)
	}
	if err := dh.GenerateKey(); err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	encode := func(value *big.Int, size int) []byte {
		encoded := make([]byte, size)
		valueBytes := value.Bytes()
		copy(encoded[len(encoded)-len(valueBytes):], valueBytes)
		return encoded
	}
	pMinusOne := new(big.Int).Sub(dh.P, big.NewInt(1))
	validTwo := encode(big.NewInt(2), 384)
	tests := map[string][]byte{
		"zero":        make([]byte, 384),
		"one":         encode(big.NewInt(1), 384),
		"p-minus-one": encode(pMinusOne, 384),
		"p":           encode(dh.P, 384),
		"short":       validTwo[1:],
		"long":        append([]byte{0}, validTwo...),
	}
	for name, peerKey := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := dh.ComputeSharedSecret(peerKey); err == nil {
				t.Fatal("ComputeSharedSecret() accepted an invalid peer key")
			}
		})
	}
}
