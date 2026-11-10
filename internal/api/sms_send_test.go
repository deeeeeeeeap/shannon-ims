package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/device"
	"github.com/1239t/vohive/internal/vowifihost"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/gin-gonic/gin"
)

const smsSendTestIMSI = "001010123456789"

// smsSendModemBackend is a modem backend that takes prepared messages and
// remembers what it was given.
type smsSendModemBackend struct {
	ussdDeviceBackendStub
	imsi    string
	sendErr error

	mu          sync.Mutex
	submissions []*smscodec.Submission
}

var (
	_ backend.PreparedSMSSender = (*smsSendModemBackend)(nil)
	_ backend.SMSCProvider      = (*smsSendModemBackend)(nil)
)

func (b *smsSendModemBackend) GetIMSI(context.Context) (string, error) { return b.imsi, nil }

func (b *smsSendModemBackend) GetSMSC(context.Context) (string, error) { return "+55500", nil }

func (b *smsSendModemBackend) SendPreparedSMS(_ context.Context, submission *smscodec.Submission) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.submissions = append(b.submissions, submission)
	return b.sendErr
}

func (b *smsSendModemBackend) sent() []*smscodec.Submission {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*smscodec.Submission(nil), b.submissions...)
}

// smsSendIMSService stands in for the IMS engine behind a Wi-Fi Calling session.
type smsSendIMSService struct {
	outcome messaging.SendOutcome
	sendErr error

	mu    sync.Mutex
	peers []string
}

var _ messaging.Service = (*smsSendIMSService)(nil)

func (s *smsSendIMSService) SendSMS(_ context.Context, peer, _ string, _ []messaging.SMSPart) (messaging.SendOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = append(s.peers, peer)
	return s.outcome, s.sendErr
}

func (*smsSendIMSService) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*smsSendIMSService) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*smsSendIMSService) CancelUSSD(context.Context, string) error { return nil }

func (s *smsSendIMSService) sentTo() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.peers...)
}

func newSMSSendTestServer(t *testing.T, workers ...*device.Worker) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	openTestDB(t)
	pool := device.NewPool(&config.Config{})
	for _, w := range workers {
		injectWorker(pool, w)
	}
	return &Server{pool: pool}
}

// startSMSSendTestSession gives a device of the server a Wi-Fi Calling session
// that is ready for messages and hands them to service.
func startSMSSendTestSession(t *testing.T, s *Server, deviceID string, service messaging.Service) {
	t.Helper()
	field := reflect.ValueOf(s.pool).Elem().FieldByName("vowifiHost")
	if !field.IsValid() {
		t.Fatal("the pool has no vowifiHost field")
	}
	host := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	manager, _ := host.Interface().(*vowifihost.Manager)
	if manager == nil {
		manager = vowifihost.NewManager()
		host.Set(reflect.ValueOf(manager))
	}

	inst := &runtimehost.Instance{}
	setNestedPrivateField(t, inst, []string{"deviceID"}, deviceID)
	setNestedPrivateField(t, inst, []string{"state"}, runtimehost.State{SMSReady: true})
	setNestedPrivateField(t, inst, []string{"svc"}, service)
	manager.RuntimeStore().SetInstance(deviceID, inst)
}

type smsSendResponse struct {
	Status        string  `json:"status"`
	Message       string  `json:"message"`
	Device        string  `json:"device"`
	Phone         string  `json:"phone"`
	MessageID     *string `json:"message_id"`
	PartsTotal    *int    `json:"parts_total"`
	DeliveryState *string `json:"delivery_state"`
}

func (r smsSendResponse) tracking() (messageID string, parts int, state string) {
	if r.MessageID != nil {
		messageID = *r.MessageID
	}
	if r.PartsTotal != nil {
		parts = *r.PartsTotal
	}
	if r.DeliveryState != nil {
		state = *r.DeliveryState
	}
	return messageID, parts, state
}

func postSMSSend(t *testing.T, s *Server, request map[string]string) (int, smsSendResponse) {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/sms/send", strings.NewReader(string(body)))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleSendSMS(ctx)

	var response smsSendResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("the response with status %d is not JSON: %v", rec.Code, err)
	}
	return rec.Code, response
}

func sentSMSHistory(t *testing.T) []db.SMS {
	t.Helper()
	var rows []db.SMS
	if err := db.DB.Where("type = ?", 2).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("read the message history: %v", err)
	}
	return rows
}

func TestHandleSendSMSOverTheModemReportsTheRealPartCount(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})
	text := strings.Repeat("A", 400)

	code, response := postSMSSend(t, server, map[string]string{"device_id": " dev-1 ", "phone": "+1 (202) 555-0123", "message": text})
	if code != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", code, response.Message)
	}
	if response.Status != "ok" || response.Device != "dev-1" || response.Phone != "+1 (202) 555-0123" {
		t.Fatalf("response = %+v", response)
	}
	if response.Message != "短信中心已确认提交（不代表收件人已收到）" {
		t.Fatalf("message = %q", response.Message)
	}
	if messageID, parts, state := response.tracking(); messageID != "" || parts != 3 || state != "acked" {
		t.Fatalf("message_id=%q parts_total=%d delivery_state=%q, want none, 3 and acked", messageID, parts, state)
	}

	sent := modemBackend.sent()
	if len(sent) != 1 || sent[0].To() != "+12025550123" || sent[0].PartCount() != 3 {
		t.Fatalf("the modem was given %d messages", len(sent))
	}
	rows := sentSMSHistory(t)
	if len(rows) != 1 || rows[0].Recipient != "+12025550123" || rows[0].Status != 2 || rows[0].IMSI != smsSendTestIMSI {
		t.Fatalf("history rows = %d, want the one sent message", len(rows))
	}
}

func TestHandleSendSMSReportsAModemFailureAndRecordsIt(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI, sendErr: errors.New("+CMS ERROR: 38")}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})

	code, response := postSMSSend(t, server, map[string]string{"device_id": "dev-1", "phone": "10086", "message": "synthetic"})
	if code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if response.Status != "error" || response.Message != "发送失败: +CMS ERROR: 38" || response.Device != "dev-1" || response.Phone != "10086" {
		t.Fatalf("response = %+v", response)
	}
	// An empty message_id keeps the web console treating this as a failure.
	if messageID, parts, state := response.tracking(); response.MessageID == nil || messageID != "" || parts != 1 || state != "failed" {
		t.Fatalf("message_id=%q parts_total=%d delivery_state=%q, want empty, 1 and failed", messageID, parts, state)
	}

	rows := sentSMSHistory(t)
	if len(rows) != 1 || rows[0].Recipient != "10086" || rows[0].Status != 3 {
		t.Fatalf("history rows = %d, want the one failed message", len(rows))
	}
}

func TestHandleSendSMSRejectsWhatCannotBeSent(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})

	cases := []struct {
		name    string
		request map[string]string
		want    string
	}{
		{name: "letters in the number", request: map[string]string{"device_id": "dev-1", "phone": "someone", "message": "synthetic"},
			want: "参数错误: " + smscodec.ErrDestinationInvalid.Error()},
		{name: "number too long", request: map[string]string{"device_id": "dev-1", "phone": strings.Repeat("1", 21), "message": "synthetic"},
			want: "参数错误: " + smscodec.ErrDestinationTooLong.Error()},
		{name: "unknown encoding", request: map[string]string{"device_id": "dev-1", "phone": "10086", "message": "synthetic", "encoding": "klingon"},
			want: "短信编码参数错误: unsupported SMS encoding: klingon"},
	}
	for _, tc := range cases {
		code, response := postSMSSend(t, server, tc.request)
		if code != http.StatusBadRequest || response.Status != "error" || response.Message != tc.want {
			t.Fatalf("%s: status = %d, message = %q, want 400 and %q", tc.name, code, response.Message, tc.want)
		}
	}

	for _, request := range []map[string]string{
		{"device_id": "dev-1", "message": "synthetic"},
		{"device_id": "dev-1", "phone": "10086"},
	} {
		code, response := postSMSSend(t, server, request)
		if code != http.StatusBadRequest || !strings.HasPrefix(response.Message, "参数错误: ") {
			t.Fatalf("a request without phone or message: status = %d, message = %q", code, response.Message)
		}
	}

	if sent := modemBackend.sent(); len(sent) != 0 {
		t.Fatalf("the modem was given %d messages for requests that cannot be sent", len(sent))
	}
	if rows := sentSMSHistory(t); len(rows) != 0 {
		t.Fatalf("%d history rows were written for requests that were never sent", len(rows))
	}
}

func TestHandleSendSMSPicksTheDevice(t *testing.T) {
	first := &smsSendModemBackend{imsi: "001010000000001"}
	second := &smsSendModemBackend{imsi: "001010000000002"}
	server := newSMSSendTestServer(t,
		&device.Worker{ID: "dev-a", Backend: first},
		&device.Worker{ID: "dev-b", Backend: second},
	)

	for _, tc := range []struct {
		name    string
		request map[string]string
		want    string
	}{
		{name: "no device named", request: map[string]string{"phone": "10086", "message": "synthetic"},
			want: "存在多个设备时必须指定 device_id 或 imsi"},
		{name: "unknown device", request: map[string]string{"device_id": "dev-x", "phone": "10086", "message": "synthetic"},
			want: "设备未找到: dev-x"},
		{name: "unknown subscriber", request: map[string]string{"imsi": "001019999999999", "phone": "10086", "message": "synthetic"},
			want: "未找到匹配 IMSI 的设备: 001019999999999"},
	} {
		code, response := postSMSSend(t, server, tc.request)
		if code != http.StatusNotFound || response.Message != tc.want {
			t.Fatalf("%s: status = %d, message = %q, want 404 and %q", tc.name, code, response.Message, tc.want)
		}
	}

	code, response := postSMSSend(t, server, map[string]string{"imsi": "001010000000002", "phone": "10086", "message": "synthetic"})
	if code != http.StatusOK || response.Device != "dev-b" {
		t.Fatalf("by subscriber: status = %d, device = %q, want 200 and dev-b", code, response.Device)
	}
	if len(first.sent()) != 0 || len(second.sent()) != 1 {
		t.Fatalf("messages sent: %d from dev-a and %d from dev-b, want 0 and 1", len(first.sent()), len(second.sent()))
	}
}

func TestHandleSendSMSUsesTheOnlyDeviceWhenNoneIsNamed(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})

	code, response := postSMSSend(t, server, map[string]string{"phone": "10086", "message": "synthetic"})
	if code != http.StatusOK || response.Device != "dev-1" || len(modemBackend.sent()) != 1 {
		t.Fatalf("status = %d, device = %q, %d messages sent", code, response.Device, len(modemBackend.sent()))
	}
}

func TestHandleSendSMSOverIMSReturnsTheTrackingID(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})
	service := &smsSendIMSService{outcome: messaging.SendOutcome{MessageID: "ims-out-8", PartsTotal: 1, DeliveryState: "pending"}}
	startSMSSendTestSession(t, server, "dev-1", service)

	code, response := postSMSSend(t, server, map[string]string{"device_id": "dev-1", "phone": "+1 202-555-0123", "message": "synthetic"})
	if code != http.StatusOK || response.Status != "ok" || response.Message != "短信已提交，等待运营商回执" {
		t.Fatalf("status = %d, response = %+v", code, response)
	}
	if messageID, parts, state := response.tracking(); messageID != "ims-out-8" || parts != 1 || state != "pending" {
		t.Fatalf("message_id=%q parts_total=%d delivery_state=%q", messageID, parts, state)
	}
	if peers := service.sentTo(); len(peers) != 1 || peers[0] != "+12025550123" {
		t.Fatalf("the IMS engine was called %d times", len(peers))
	}
	if sent := modemBackend.sent(); len(sent) != 0 {
		t.Fatalf("the modem sent %d messages while the session was up", len(sent))
	}
}

func TestHandleSendSMSOverIMSReportsAFailureAndRecordsIt(t *testing.T) {
	modemBackend := &smsSendModemBackend{imsi: smsSendTestIMSI}
	server := newSMSSendTestServer(t, &device.Worker{ID: "dev-1", Backend: modemBackend})
	service := &smsSendIMSService{
		outcome: messaging.SendOutcome{MessageID: "ims-out-9", PartsTotal: 1, DeliveryState: "failed"},
		sendErr: errors.New("synthetic IMS failure"),
	}
	startSMSSendTestSession(t, server, "dev-1", service)

	code, response := postSMSSend(t, server, map[string]string{"device_id": "dev-1", "phone": "10086", "message": "synthetic"})
	if code != http.StatusInternalServerError || response.Message != "VoWiFi 短信发送失败: synthetic IMS failure" {
		t.Fatalf("status = %d, message = %q", code, response.Message)
	}
	if messageID, parts, state := response.tracking(); messageID != "ims-out-9" || parts != 1 || state != "failed" {
		t.Fatalf("message_id=%q parts_total=%d delivery_state=%q", messageID, parts, state)
	}

	rows := sentSMSHistory(t)
	if len(rows) != 1 || rows[0].MessageID != "ims-out-9" || rows[0].Recipient != "10086" || rows[0].Status != 3 {
		t.Fatalf("history rows = %d, want the one failed message", len(rows))
	}
}
