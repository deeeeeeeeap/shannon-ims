package sim

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

type efdirMock struct {
	opened []string
	closed []int
	rec1   string // EF_DIR 记录 1 的 hex(不含 SW)
}

func (e *efdirMock) DeviceID() string                                      { return "test" }
func (e *efdirMock) ExecuteATSilent(string, time.Duration) (string, error) { return "", nil }
func (e *efdirMock) OpenLogicalChannel(aid string) (int, error) {
	e.opened = append(e.opened, aid)
	return 1, nil
}
func (e *efdirMock) CloseLogicalChannel(ch int) error { e.closed = append(e.closed, ch); return nil }
func (e *efdirMock) TransmitAPDU(ch int, hexAPDU string) (string, error) {
	cmd, _ := hex.DecodeString(hexAPDU)
	if len(cmd) < 2 {
		return "6700", nil
	}
	switch cmd[1] {
	case 0xA4: // SELECT MF / EF_DIR → 成功
		return "6200" + "9000", nil
	case 0xB2: // READ RECORD
		if cmd[2] == 1 {
			return e.rec1 + "9000", nil
		}
		return "836A", nil // 6A83 字节序反转,验证鲁棒性
	}
	return "9000", nil
}

func TestIsRecordNotFoundByteOrderRobust(t *testing.T) {
	if !isRecordNotFound(0x6A, 0x83) || !isRecordNotFound(0x83, 0x6A) {
		t.Fatal("6A83 两种字节序都应判为记录不存在")
	}
	if !isRecordNotFound(0x6A, 0x82) || !isRecordNotFound(0x82, 0x6A) {
		t.Fatal("6A82 两种字节序都应判为记录不存在")
	}
	if isRecordNotFound(0x90, 0x00) {
		t.Fatal("9000 不应判为记录不存在")
	}
}

func TestExtractAID4FNested(t *testing.T) {
	rec, _ := hex.DecodeString("61164F10A0000000871002FFFFFFFF890709000050025531")
	aid := extractAID4F(rec)
	if strings.ToUpper(hex.EncodeToString(aid)) != "A0000000871002FFFFFFFF8907090000" {
		t.Fatalf("提取 AID = %X", aid)
	}
}
