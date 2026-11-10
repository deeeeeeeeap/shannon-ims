package notify

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/device"
	"github.com/1239t/vohive/pkg/smscodec"
)

const smsCommandTestIMSI = "001010123456789"

// smsCommandBackend is a modem backend for the /send command. Only what a send
// uses is implemented; the embedded interface is left nil on purpose, so a call
// to anything else fails the test loudly.
type smsCommandBackend struct {
	backend.DeviceBackend
	sendErr error

	mu   sync.Mutex
	sent []*smscodec.Submission
}

var _ backend.PreparedSMSSender = (*smsCommandBackend)(nil)

func (*smsCommandBackend) Mode() string { return backend.BackendAT }

func (*smsCommandBackend) GetIMSI(context.Context) (string, error) { return smsCommandTestIMSI, nil }

func (b *smsCommandBackend) SendPreparedSMS(_ context.Context, submission *smscodec.Submission) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, submission)
	return b.sendErr
}

func (b *smsCommandBackend) sentCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sent)
}

// smsCommandReplies collects what the command tells the chat afterwards.
type smsCommandReplies struct{ texts chan string }

func newSMSCommandReplies() *smsCommandReplies {
	return &smsCommandReplies{texts: make(chan string, 4)}
}

func (r *smsCommandReplies) Reply(text string) { r.texts <- text }

func (r *smsCommandReplies) next(t *testing.T) string {
	t.Helper()
	select {
	case text := <-r.texts:
		return text
	case <-time.After(5 * time.Second):
		t.Fatal("the command never reported how the send ended")
		return ""
	}
}

func (r *smsCommandReplies) expectNone(t *testing.T) {
	t.Helper()
	select {
	case text := <-r.texts:
		t.Fatalf("unexpected reply: %q", text)
	case <-time.After(50 * time.Millisecond):
	}
}

func newSMSCommandManager(t *testing.T, workers ...*device.Worker) *Manager {
	t.Helper()
	if err := db.Init(filepath.Join(t.TempDir(), "sms.db")); err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	t.Cleanup(func() {
		if db.DB == nil {
			return
		}
		if sqlDB, err := db.DB.DB(); err == nil && sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	pool := device.NewPool(&config.Config{})
	field := reflect.ValueOf(pool).Elem().FieldByName("workers")
	if !field.IsValid() {
		t.Fatal("the pool has no workers field")
	}
	registry := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	for _, w := range workers {
		registry.SetMapIndex(reflect.ValueOf(w.ID), reflect.ValueOf(w))
	}
	return &Manager{pool: pool}
}

func sentSMSCommandHistory(t *testing.T) []db.SMS {
	t.Helper()
	var rows []db.SMS
	if err := db.DB.Where("type = ?", 2).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("read the message history: %v", err)
	}
	return rows
}

func TestSendCommandSendsAndRecordsTheMessage(t *testing.T) {
	modemBackend := &smsCommandBackend{}
	manager := newSMSCommandManager(t, &device.Worker{
		ID:      "dev1",
		Config:  config.DeviceConfig{Name: "Office"},
		Backend: modemBackend,
	})
	replies := newSMSCommandReplies()

	accepted := manager.handleCmdSendSMS(replies, []string{"dev1", "+12025550123", "synthetic", "text"})
	if want := "发送短信 / 已受理\n设备    Office (dev1)\n号码    +12025550123\n通道    蜂窝"; accepted != want {
		t.Fatalf("accepted = %q, want %q", accepted, want)
	}
	if got, want := replies.next(t), "发送短信 / 完成\n设备    Office (dev1)\n号码    +12025550123\n通道    蜂窝\n内容    synthetic text"; got != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}

	if n := modemBackend.sentCount(); n != 1 {
		t.Fatalf("the modem was given %d messages, want 1", n)
	}
	rows := sentSMSCommandHistory(t)
	if len(rows) != 1 || rows[0].Recipient != "+12025550123" || rows[0].Content != "synthetic text" || rows[0].Status != 2 {
		t.Fatalf("history rows = %d, want the one sent message", len(rows))
	}
}

func TestSendCommandRecordsAMessageThatFailed(t *testing.T) {
	modemBackend := &smsCommandBackend{sendErr: errors.New("+CMS ERROR: 38")}
	manager := newSMSCommandManager(t, &device.Worker{ID: "dev1", Backend: modemBackend})
	replies := newSMSCommandReplies()

	accepted := manager.handleCmdSendSMS(replies, []string{"dev1", "10086", "synthetic"})
	if want := "发送短信 / 已受理\n设备    dev1\n号码    10086\n通道    蜂窝"; accepted != want {
		t.Fatalf("accepted = %q, want %q", accepted, want)
	}
	if got, want := replies.next(t), "发送短信 / 失败\n设备    dev1\n号码    10086\n通道    蜂窝\n原因    +CMS ERROR: 38"; got != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}

	// A send that failed from the chat is kept in the history like one that
	// failed from the web console.
	rows := sentSMSCommandHistory(t)
	if len(rows) != 1 || rows[0].Recipient != "10086" || rows[0].Content != "synthetic" || rows[0].Status != 3 {
		t.Fatalf("history rows = %d, want the one failed message", len(rows))
	}
}

func TestSendCommandRefusesANumberThatCannotBeDialled(t *testing.T) {
	modemBackend := &smsCommandBackend{}
	manager := newSMSCommandManager(t, &device.Worker{ID: "dev1", Backend: modemBackend})
	replies := newSMSCommandReplies()

	manager.handleCmdSendSMS(replies, []string{"dev1", "someone", "synthetic"})
	want := "发送短信 / 失败\n设备    dev1\n号码    someone\n通道    蜂窝\n原因    " + smscodec.ErrDestinationInvalid.Error()
	if got := replies.next(t); got != want {
		t.Fatalf("reply = %q, want %q", got, want)
	}

	if n := modemBackend.sentCount(); n != 0 {
		t.Fatalf("the modem was given %d messages for a number that cannot be dialled", n)
	}
	if rows := sentSMSCommandHistory(t); len(rows) != 0 {
		t.Fatalf("%d history rows were written for a message that was never sent", len(rows))
	}
}

func TestSendCommandAnswersAtOnceWhenItCannotStart(t *testing.T) {
	modemBackend := &smsCommandBackend{}
	manager := newSMSCommandManager(t, &device.Worker{ID: "dev1", Backend: modemBackend})
	replies := newSMSCommandReplies()

	if got, want := manager.handleCmdSendSMS(replies, []string{"dev1", "10086"}),
		"发送短信 / 用法\n用法    /send [设备ID] [手机号] [消息]\n示例    /send ec20_1 +8613812345678 测试短信"; got != want {
		t.Fatalf("too few arguments: %q, want %q", got, want)
	}
	if got, want := manager.handleCmdSendSMS(replies, []string{"dev9", "10086", "synthetic"}),
		"发送短信 / 失败\n设备    dev9\n原因    设备未找到"; got != want {
		t.Fatalf("unknown device: %q, want %q", got, want)
	}

	replies.expectNone(t)
	if n := modemBackend.sentCount(); n != 0 {
		t.Fatalf("the modem was given %d messages", n)
	}
}
