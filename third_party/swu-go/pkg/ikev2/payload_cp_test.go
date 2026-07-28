package ikev2

import (
	"bytes"
	"testing"
)

// TestPayloadCPEncodeDecode 测试 CP 载荷的编解码
func TestPayloadCPEncodeDecode(t *testing.T) {
	// 创建测试 CP 载荷
	original := &EncryptedPayloadCP{
		CFGType: CFG_REPLY,
		Attributes: []*CPAttribute{
			{Type: INTERNAL_IP4_ADDRESS, Value: []byte{10, 0, 0, 1}},
			{Type: INTERNAL_IP4_DNS, Value: []byte{8, 8, 8, 8}},
			{Type: P_CSCF_IP4_ADDRESS, Value: []byte{192, 168, 1, 1}},
		},
	}

	// 编码
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	// 解码
	decoded, err := DecodePayloadCP(encoded)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	// 验证 CFGType
	if decoded.CFGType != original.CFGType {
		t.Errorf("CFGType 不匹配: got %d, want %d", decoded.CFGType, original.CFGType)
	}

	// 验证属性数量
	if len(decoded.Attributes) != len(original.Attributes) {
		t.Fatalf("属性数量不匹配: got %d, want %d", len(decoded.Attributes), len(original.Attributes))
	}

	// 验证每个属性
	for i, attr := range decoded.Attributes {
		if attr.Type != original.Attributes[i].Type {
			t.Errorf("属性[%d] Type 不匹配: got %d, want %d", i, attr.Type, original.Attributes[i].Type)
		}
		if !bytes.Equal(attr.Value, original.Attributes[i].Value) {
			t.Errorf("属性[%d] Value 不匹配: got %v, want %v", i, attr.Value, original.Attributes[i].Value)
		}
	}
}

// TestPayloadCPDecodeEmpty 测试空数据解码
func TestPayloadCPDecodeEmpty(t *testing.T) {
	_, err := DecodePayloadCP([]byte{1, 0, 0}) // 少于 4 字节
	if err == nil {
		t.Error("预期返回错误，但没有")
	}
}
