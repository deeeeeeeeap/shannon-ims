package ikev2

import (
	"bytes"
	"net"
	"testing"
)

// TestNATDetectionHash 测试 NAT 检测哈希计算
func TestNATDetectionHash(t *testing.T) {
	spiI := uint64(0x1122334455667788)
	spiR := uint64(0)
	ip := net.ParseIP("192.168.1.1").To4()
	port := uint16(500)

	hash := CalculateNATDetectionHash(spiI, spiR, ip, port)

	// SHA-1 输出应该是 20 字节
	if len(hash) != 20 {
		t.Errorf("哈希长度错误: got %d, want 20", len(hash))
	}

	// 相同输入应产生相同输出
	hash2 := CalculateNATDetectionHash(spiI, spiR, ip, port)
	if !bytes.Equal(hash, hash2) {
		t.Error("相同输入产生不同的哈希")
	}

	// 不同输入应产生不同输出
	hash3 := CalculateNATDetectionHash(spiI, spiR, ip, 4500)
	if bytes.Equal(hash, hash3) {
		t.Error("不同端口应产生不同的哈希")
	}
}

// TestCreateNATDetectionNotify 测试创建 NAT 检测通知载荷
func TestCreateNATDetectionNotify(t *testing.T) {
	hash := make([]byte, 20)
	for i := range hash {
		hash[i] = byte(i)
	}

	payload := CreateNATDetectionNotify(NAT_DETECTION_SOURCE_IP, hash)

	if payload.NotifyType != NAT_DETECTION_SOURCE_IP {
		t.Errorf("NotifyType 错误: got %d, want %d", payload.NotifyType, NAT_DETECTION_SOURCE_IP)
	}

	if !bytes.Equal(payload.NotifyData, hash) {
		t.Error("NotifyData 不匹配")
	}

	if payload.ProtocolID != ProtoIKE {
		t.Errorf("ProtocolID 错误: got %d, want %d", payload.ProtocolID, ProtoIKE)
	}
}
