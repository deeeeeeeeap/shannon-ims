package ipsec

import (
	"bytes"
	"testing"

	"github.com/1239t/swu-go/pkg/crypto"
)

// TestESPEncapsulateDecapsulate 测试 ESP 封装和解封装
func TestESPEncapsulateDecapsulate(t *testing.T) {
	// 创建加密器
	enc, err := crypto.GetEncrypter(20) // AES-GCM-16
	if err != nil {
		t.Fatalf("获取加密器失败: %v", err)
	}

	// 创建 SA
	key := make([]byte, 20) // 16 key + 4 salt
	copy(key, []byte("1234567890123456salt"))

	sa := NewSecurityAssociation(0x12345678, enc, key, nil)

	// 模拟 IPv4 数据包 (IP 头: version=4)
	plainPacket := make([]byte, 40)
	plainPacket[0] = 0x45 // IPv4, IHL=5

	// 封装
	espPacket, err := Encapsulate(plainPacket, sa)
	if err != nil {
		t.Fatalf("ESP 封装失败: %v", err)
	}

	t.Logf("原始包大小: %d, ESP 包大小: %d", len(plainPacket), len(espPacket))

	// 创建接收端 SA (SPI 等于报文头里的 SPI)
	saIn := NewSecurityAssociation(0x12345678, enc, key, nil)

	// 解封装
	decrypted, err := Decapsulate(espPacket, saIn)
	if err != nil {
		t.Fatalf("ESP 解封装失败: %v", err)
	}

	if !bytes.Equal(plainPacket, decrypted) {
		t.Errorf("解封装结果不匹配")
	}
}

// TestSecurityAssociationSequenceNumber 测试序列号递增
func TestSecurityAssociationSequenceNumber(t *testing.T) {
	sa := &SecurityAssociation{}

	seq1 := sa.NextSequenceNumber()
	seq2 := sa.NextSequenceNumber()
	seq3 := sa.NextSequenceNumber()

	if seq1 != 1 {
		t.Errorf("第一个序列号应为 1, got %d", seq1)
	}
	if seq2 != 2 {
		t.Errorf("第二个序列号应为 2, got %d", seq2)
	}
	if seq3 != 3 {
		t.Errorf("第三个序列号应为 3, got %d", seq3)
	}
}
