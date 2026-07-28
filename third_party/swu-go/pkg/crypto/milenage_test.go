package crypto

import (
	"encoding/hex"
	"testing"
)

// 测试向量来自 3GPP TS 35.208
func TestMilenageF2F5(t *testing.T) {
	// 测试向量 1
	k, _ := hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	rand, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")

	m, err := NewMilenage(k, op, false)
	if err != nil {
		t.Fatalf("NewMilenage 失败: %v", err)
	}

	res, ak, err := m.F2F5(rand)
	if err != nil {
		t.Fatalf("F2F5 失败: %v", err)
	}

	t.Logf("RES: %s", hex.EncodeToString(res))
	t.Logf("AK: %s", hex.EncodeToString(ak))

	// 验证 RES 和 AK 不为空
	if len(res) != 8 || len(ak) != 6 {
		t.Errorf("输出长度错误: RES=%d, AK=%d", len(res), len(ak))
	}
}

func TestMilenageF3F4(t *testing.T) {
	k, _ := hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	rand, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")

	m, err := NewMilenage(k, op, false)
	if err != nil {
		t.Fatalf("NewMilenage 失败: %v", err)
	}

	ck, err := m.F3(rand)
	if err != nil {
		t.Fatalf("F3 失败: %v", err)
	}

	ik, err := m.F4(rand)
	if err != nil {
		t.Fatalf("F4 失败: %v", err)
	}

	t.Logf("CK: %s", hex.EncodeToString(ck))
	t.Logf("IK: %s", hex.EncodeToString(ik))

	if len(ck) != 16 || len(ik) != 16 {
		t.Errorf("输出长度错误: CK=%d, IK=%d", len(ck), len(ik))
	}
}

func TestMilenageF1(t *testing.T) {
	k, _ := hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	rand, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")
	sqn, _ := hex.DecodeString("ff9bb4d0b607")
	amf, _ := hex.DecodeString("b9b9")

	m, err := NewMilenage(k, op, false)
	if err != nil {
		t.Fatalf("NewMilenage 失败: %v", err)
	}

	macA, macS, err := m.F1(rand, sqn, amf)
	if err != nil {
		t.Fatalf("F1 失败: %v", err)
	}

	t.Logf("MAC-A: %s", hex.EncodeToString(macA))
	t.Logf("MAC-S: %s", hex.EncodeToString(macS))

	if len(macA) != 8 || len(macS) != 8 {
		t.Errorf("输出长度错误: MAC-A=%d, MAC-S=%d", len(macA), len(macS))
	}
}

func TestMilenageGenerateAUTN(t *testing.T) {
	k, _ := hex.DecodeString("465b5ce8b199b49faa5f0a2ee238a6bc")
	op, _ := hex.DecodeString("cdc202d5123e20f62b6d676ac72cb318")
	rand, _ := hex.DecodeString("23553cbe9637a89d218ae64dae47bf35")
	sqn, _ := hex.DecodeString("ff9bb4d0b607")
	amf, _ := hex.DecodeString("8000")

	m, err := NewMilenage(k, op, false)
	if err != nil {
		t.Fatalf("NewMilenage 失败: %v", err)
	}

	autn, err := m.GenerateAUTN(rand, sqn, amf)
	if err != nil {
		t.Fatalf("GenerateAUTN 失败: %v", err)
	}

	t.Logf("AUTN: %s", hex.EncodeToString(autn))

	if len(autn) != 16 {
		t.Errorf("AUTN 长度错误: %d", len(autn))
	}
}
