package crypto

import (
	"bytes"
	"testing"
)

// TestPrfPlus 测试 PRF+ 密钥派生函数
func TestPrfPlus(t *testing.T) {
	prf := PRF_HMAC_SHA2_256
	key := []byte("test-key-1234567890")
	seed := []byte("test-seed-data")

	// 生成 64 字节
	result, err := PrfPlus(prf, key, seed, 64)
	if err != nil {
		t.Fatalf("PrfPlus 失败: %v", err)
	}

	if len(result) != 64 {
		t.Errorf("结果长度错误: got %d, want 64", len(result))
	}

	// 再次生成，结果应该相同
	result2, err := PrfPlus(prf, key, seed, 64)
	if err != nil {
		t.Fatalf("PrfPlus 第二次调用失败: %v", err)
	}

	if !bytes.Equal(result, result2) {
		t.Error("相同输入的 PrfPlus 结果不一致")
	}
}

// TestAESGCMEncryptDecrypt 测试 AES-GCM 加解密
func TestAESGCMEncryptDecrypt(t *testing.T) {
	enc, err := GetEncrypter(20) // ENCR_AES_GCM_16
	if err != nil {
		t.Fatalf("获取加密器失败: %v", err)
	}

	// Key: 16 bytes + 4 bytes salt = 20 bytes
	key := []byte("1234567890123456salt")
	plaintext := []byte("Hello, IKEv2 World!")
	aad := []byte("additional-auth-data")

	// 生成 IV
	iv, err := RandomBytes(enc.IVSize())
	if err != nil {
		t.Fatalf("生成 IV 失败: %v", err)
	}

	// 加密
	ciphertext, err := enc.Encrypt(plaintext, key, iv, aad)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := enc.Decrypt(ciphertext, key, iv, aad)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("解密结果不匹配: got %s, want %s", decrypted, plaintext)
	}
}

// TestAESCBCEncryptDecrypt 测试 AES-CBC 加解密
func TestAESCBCEncryptDecrypt(t *testing.T) {
	enc, err := GetEncrypter(12) // ENCR_AES_CBC
	if err != nil {
		t.Fatalf("获取加密器失败: %v", err)
	}

	key := []byte("1234567890123456") // 16 bytes
	// 明文必须是块对齐的 (16 bytes)
	plaintext := []byte("HelloIKEv2World!")

	iv, err := RandomBytes(enc.IVSize())
	if err != nil {
		t.Fatalf("生成 IV 失败: %v", err)
	}

	// 加密
	ciphertext, err := enc.Encrypt(plaintext, key, iv, nil)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := enc.Decrypt(ciphertext, key, iv, nil)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("解密结果不匹配: got %s, want %s", decrypted, plaintext)
	}
}

// TestRandomBytes 测试随机字节生成
func TestRandomBytes(t *testing.T) {
	b1, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes 失败: %v", err)
	}

	b2, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes 第二次调用失败: %v", err)
	}

	if bytes.Equal(b1, b2) {
		t.Error("两次 RandomBytes 调用不应返回相同的结果")
	}

	if len(b1) != 32 {
		t.Errorf("长度错误: got %d, want 32", len(b1))
	}
}
