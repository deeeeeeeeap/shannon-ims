package device

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/eventhost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// smsSendModemStub is a modem backend that takes prepared messages and
// remembers what it was given.
type smsSendModemStub struct {
	workerStatusBackendStub
	imsi    string
	sendErr error

	mu          sync.Mutex
	submissions []*smscodec.Submission
	contextErrs []error
	timeLeft    []time.Duration
}

var _ backend.PreparedSMSSender = (*smsSendModemStub)(nil)

func (b *smsSendModemStub) GetIMSI(context.Context) (string, error) { return b.imsi, nil }

func (b *smsSendModemStub) SendPreparedSMS(ctx context.Context, submission *smscodec.Submission) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.submissions = append(b.submissions, submission)
	b.contextErrs = append(b.contextErrs, ctx.Err())
	left := time.Duration(-1)
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	b.timeLeft = append(b.timeLeft, left)
	return b.sendErr
}

func (b *smsSendModemStub) sent() []*smscodec.Submission {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*smscodec.Submission(nil), b.submissions...)
}

// smsSendTextOnlyStub is a modem backend that cannot take a prepared message.
type smsSendTextOnlyStub struct {
	workerStatusBackendStub

	mu    sync.Mutex
	to    []string
	texts []string
}

func (b *smsSendTextOnlyStub) SendSMS(_ context.Context, to, text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.to = append(b.to, to)
	b.texts = append(b.texts, text)
	return nil
}

// smsSendIMSService stands in for the IMS engine behind a Wi-Fi Calling session.
type smsSendIMSService struct {
	outcome messaging.SendOutcome
	sendErr error

	mu      sync.Mutex
	calls   int
	peer    string
	content string
	parts   []messaging.SMSPart
}

var _ messaging.Service = (*smsSendIMSService)(nil)

func (s *smsSendIMSService) SendSMS(_ context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.peer, s.content = peer, content
	s.parts = make([]messaging.SMSPart, len(parts))
	for i := range parts {
		s.parts[i] = parts[i]
		s.parts[i].Body = append([]byte(nil), parts[i].Body...)
	}
	return s.outcome, s.sendErr
}

func (*smsSendIMSService) SendUSSD(context.Context, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*smsSendIMSService) ContinueUSSD(context.Context, string, string) (*messaging.USSDResult, error) {
	return nil, nil
}

func (*smsSendIMSService) CancelUSSD(context.Context, string) error { return nil }

func (s *smsSendIMSService) seen() (calls int, peer, content string, parts []messaging.SMSPart) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.peer, s.content, append([]messaging.SMSPart(nil), s.parts...)
}

func newSMSSendTestPool(t *testing.T, workers ...*Worker) *Pool {
	t.Helper()
	pool := NewPool(&config.Config{})
	for _, w := range workers {
		w.Pool = pool
		pool.workers[w.ID] = w
	}
	return pool
}

// newSMSSendIMSPool returns a pool whose one device has a Wi-Fi Calling
// session that is ready for messages, and that device's ID. Submissions the
// session accepts are written to the history the way a running system does it.
func newSMSSendIMSPool(t *testing.T, service *smsSendIMSService) (*Pool, string) {
	t.Helper()
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, service)
	setIncomingSMSTestIMSI(pool.workers[deviceID], incomingSMSTestIMSI)
	setRuntimeInstanceFieldForPoolSMSTest(t, pool.voWiFiRuntimeStore().Instance(deviceID), "dispatch",
		eventhost.Dispatcher(poolVoWiFiRuntimeDispatcher{pool: pool}))
	return pool, deviceID
}

func sentSMSHistory(t *testing.T) []db.SMS {
	t.Helper()
	var rows []db.SMS
	if err := db.DB.Where("type = ?", smsHistoryTypeSent).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("read the message history: %v", err)
	}
	return rows
}

func TestSendSMSOverTheModemCountsThePartsAndRecordsTheMessage(t *testing.T) {
	openIncomingSMSTestDB(t)
	modemStub := &smsSendModemStub{imsi: incomingSMSTestIMSI}
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: modemStub})
	text := strings.Repeat("A", 400)

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: " dev1 ", To: " +1 (202) 555-0123 ", Text: text})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	want := SMSSendResult{DeviceID: "dev1", Channel: SMSChannelCellular, To: "+12025550123", PartsTotal: 3, DeliveryState: "acked"}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}

	sent := modemStub.sent()
	if len(sent) != 1 {
		t.Fatalf("the modem was given %d messages, want 1", len(sent))
	}
	if sent[0].To() != "+12025550123" || sent[0].PartCount() != 3 {
		t.Fatalf("the modem was given a message to %q in %d parts", sent[0].To(), sent[0].PartCount())
	}
	for i := 0; i < sent[0].PartCount(); i++ {
		if tpdu := sent[0].TPDU(i); len(tpdu) == 0 || tpdu[0]&0x20 != 0 {
			t.Fatalf("part %d asks for a status report, which only SMS over IMS does", i)
		}
	}

	rows := sentSMSHistory(t)
	if len(rows) != 1 {
		t.Fatalf("the history has %d sent messages, want 1", len(rows))
	}
	if row := rows[0]; row.IMSI != incomingSMSTestIMSI || row.Recipient != "+12025550123" || row.Content != text || row.Status != smsHistoryStatusSent {
		t.Fatalf("history row: recipient %q, status %d, %d characters", row.Recipient, row.Status, len(row.Content))
	}
}

func TestSendSMSRecordsAMessageTheModemRefused(t *testing.T) {
	openIncomingSMSTestDB(t)
	refused := errors.New("+CMS ERROR: 38")
	modemStub := &smsSendModemStub{imsi: incomingSMSTestIMSI, sendErr: refused}
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: modemStub})

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "10086", Text: "synthetic"})
	if !errors.Is(err, refused) {
		t.Fatalf("SendSMS error = %v, want the modem's", err)
	}
	if errors.Is(err, ErrSMSRequestInvalid) {
		t.Fatal("a failure of the modem is reported as a bad request")
	}
	want := SMSSendResult{DeviceID: "dev1", Channel: SMSChannelCellular, To: "10086", PartsTotal: 1, DeliveryState: "failed"}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}

	rows := sentSMSHistory(t)
	if len(rows) != 1 {
		t.Fatalf("the history has %d sent messages, want the failed one", len(rows))
	}
	if row := rows[0]; row.Recipient != "10086" || row.Content != "synthetic" || row.Status != smsHistoryStatusFailed {
		t.Fatalf("history row: recipient %q, status %d", row.Recipient, row.Status)
	}
}

func TestSendSMSRefusesWhatCannotBeSentBeforeTouchingAChannel(t *testing.T) {
	cases := []struct {
		name     string
		to, text string
		encoding smscodec.SMSEncoding
		want     error
	}{
		{name: "letters in the number", to: "someone", text: "synthetic", want: smscodec.ErrDestinationInvalid},
		{name: "no number", to: "  ", text: "synthetic", want: smscodec.ErrDestinationEmpty},
		{name: "number too long", to: strings.Repeat("1", 21), text: "synthetic", want: smscodec.ErrDestinationTooLong},
		{name: "no text", to: "10086", text: "", want: smscodec.ErrMessageEmpty},
		{name: "unknown encoding", to: "10086", text: "synthetic", encoding: "klingon"},
	}

	check := func(t *testing.T, pool *Pool, deviceID string, channel SMSChannel, touched func() int) {
		t.Helper()
		for _, tc := range cases {
			result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: deviceID, To: tc.to, Text: tc.text, Encoding: tc.encoding})
			if !errors.Is(err, ErrSMSRequestInvalid) {
				t.Fatalf("%s: error = %v, want ErrSMSRequestInvalid", tc.name, err)
			}
			if tc.want != nil && (!errors.Is(err, tc.want) || err.Error() != tc.want.Error()) {
				t.Fatalf("%s: error = %q, want %q unchanged", tc.name, err, tc.want)
			}
			if result.Channel != channel || result.PartsTotal != 0 || result.DeliveryState != "failed" || result.MessageID != "" {
				t.Fatalf("%s: result = %+v", tc.name, result)
			}
		}
		if n := touched(); n != 0 {
			t.Fatalf("the channel was used %d times for requests that cannot be sent", n)
		}
		if rows := sentSMSHistory(t); len(rows) != 0 {
			t.Fatalf("%d history rows were written for requests that were never sent", len(rows))
		}
	}

	t.Run("modem", func(t *testing.T) {
		openIncomingSMSTestDB(t)
		modemStub := &smsSendModemStub{imsi: incomingSMSTestIMSI}
		pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: modemStub})
		check(t, pool, "dev1", SMSChannelCellular, func() int { return len(modemStub.sent()) })
	})
	t.Run("ims", func(t *testing.T) {
		openIncomingSMSTestDB(t)
		service := &smsSendIMSService{}
		pool, deviceID := newSMSSendIMSPool(t, service)
		check(t, pool, deviceID, SMSChannelIMS, func() int { calls, _, _, _ := service.seen(); return calls })
	})
}

func TestSendSMSReportsAnUnknownDevice(t *testing.T) {
	pool := newSMSSendTestPool(t)

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "nowhere", To: "10086", Text: "synthetic"})
	if !errors.Is(err, ErrSMSDeviceNotFound) {
		t.Fatalf("SendSMS error = %v, want ErrSMSDeviceNotFound", err)
	}
	if result.Channel != "" || result.DeviceID != "nowhere" || result.DeliveryState != "failed" {
		t.Fatalf("result = %+v", result)
	}
}

func TestSendSMSOverIMSAsksForAStatusReportAndLeavesTheHistoryToTheEngine(t *testing.T) {
	openIncomingSMSTestDB(t)
	service := &smsSendIMSService{outcome: messaging.SendOutcome{MessageID: " ims-out-1 ", PartsTotal: 3, DeliveryState: "PENDING"}}
	pool, deviceID := newSMSSendIMSPool(t, service)
	text := strings.Repeat("a", 400)

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: deviceID, To: "+1 202-555-0123", Text: text})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	want := SMSSendResult{DeviceID: deviceID, Channel: SMSChannelIMS, To: "+12025550123", MessageID: "ims-out-1", PartsTotal: 3, DeliveryState: "pending"}
	if result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}

	calls, peer, content, parts := service.seen()
	if calls != 1 || peer != "+12025550123" || content != text {
		t.Fatalf("the IMS engine was called %d times, for %q with %d characters", calls, peer, len(content))
	}
	if len(parts) != 3 {
		t.Fatalf("the IMS engine was given %d parts, want 3", len(parts))
	}
	for i, part := range parts {
		_, tpdu, err := smscodec.ParseRPData(part.Body)
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		if len(tpdu) < 2 || tpdu[0]&0x20 == 0 {
			t.Fatalf("part %d does not ask for a status report", i)
		}
	}

	// The engine reported the submission; SendSMS must not add a second row.
	rows := sentSMSHistory(t)
	if len(rows) != 1 {
		t.Fatalf("the history has %d sent messages, want 1", len(rows))
	}
	if row := rows[0]; row.MessageID != "ims-out-1" || row.Recipient != "+12025550123" || row.Content != text {
		t.Fatalf("history row: message ID %q, recipient %q, status %d", row.MessageID, row.Recipient, row.Status)
	}
}

func TestSendSMSOverIMSRecordsAFailedMessageOnce(t *testing.T) {
	failure := errors.New("synthetic send failure")
	cases := []struct {
		name      string
		outcome   messaging.SendOutcome
		wantState string
		wantParts int
	}{
		{name: "nothing reported", outcome: messaging.SendOutcome{}, wantState: "failed", wantParts: 1},
		{name: "tracked and timed out", outcome: messaging.SendOutcome{MessageID: "ims-out-2", PartsTotal: 1, DeliveryState: "timeout"}, wantState: "timeout", wantParts: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			openIncomingSMSTestDB(t)
			service := &smsSendIMSService{outcome: tc.outcome, sendErr: failure}
			pool, deviceID := newSMSSendIMSPool(t, service)

			result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: deviceID, To: "(10) 086", Text: "synthetic"})
			if !errors.Is(err, failure) {
				t.Fatalf("SendSMS error = %v, want the engine's", err)
			}
			want := SMSSendResult{DeviceID: deviceID, Channel: SMSChannelIMS, To: "10086", MessageID: tc.outcome.MessageID, PartsTotal: tc.wantParts, DeliveryState: tc.wantState}
			if result != want {
				t.Fatalf("result = %+v, want %+v", result, want)
			}

			rows := sentSMSHistory(t)
			if len(rows) != 1 {
				t.Fatalf("the history has %d sent messages, want the failed one", len(rows))
			}
			if row := rows[0]; row.MessageID != tc.outcome.MessageID || row.Recipient != "10086" || row.Content != "synthetic" || row.Status != smsHistoryStatusFailed {
				t.Fatalf("history row: message ID %q, recipient %q, status %d", row.MessageID, row.Recipient, row.Status)
			}
		})
	}
}

func TestSendSMSStaysOnTheSessionItStartedOn(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	oldService := &smsSendIMSService{outcome: messaging.SendOutcome{MessageID: "old"}}
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, oldService)
	barrier := &poolSMSBarrierSMSCBackend{
		workerStatusBackendStub: workerStatusBackendStub{mode: backend.BackendAT},
		entered:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	pool.workers[deviceID].Backend = barrier
	oldInstance := pool.voWiFiRuntimeStore().Instance(deviceID)

	done := make(chan error, 1)
	go func() {
		_, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: deviceID, To: "55501", Text: "synthetic"})
		done <- err
	}()
	select {
	case <-barrier.entered:
	case <-time.After(time.Second):
		t.Fatal("SendSMS did not ask for the service centre")
	}

	// While the service centre is being read the session is torn down and a
	// new, working one takes its place.
	if err := oldInstance.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	newService := &smsSendIMSService{outcome: messaging.SendOutcome{MessageID: "new"}}
	replacement := &runtimehost.Instance{}
	setRuntimeInstanceFieldForPoolSMSTest(t, replacement, "deviceID", deviceID)
	setRuntimeInstanceFieldForPoolSMSTest(t, replacement, "state", runtimehost.State{SMSReady: true})
	setRuntimeInstanceFieldForPoolSMSTest(t, replacement, "svc", messaging.Service(newService))
	pool.voWiFiRuntimeStore().SetInstance(deviceID, replacement)
	close(barrier.release)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("SendSMS succeeded although its session was stopped")
		}
	case <-time.After(time.Second):
		t.Fatal("SendSMS did not return")
	}
	if calls, _, _, _ := oldService.seen(); calls != 0 {
		t.Fatalf("the stopped session sent %d messages", calls)
	}
	if calls, _, _, _ := newService.seen(); calls != 0 {
		t.Fatalf("the message moved to the session that replaced the one it started on (%d sends)", calls)
	}
}

func TestSendSMSOnTheModemIsNotAbandonedWithTheCallerButIsBounded(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	modemStub := &smsSendModemStub{}
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: modemStub})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pool.SendSMS(ctx, SMSSendRequest{DeviceID: "dev1", To: "10086", Text: "synthetic"}); err != nil {
		t.Fatalf("SendSMS: %v", err)
	}

	modemStub.mu.Lock()
	defer modemStub.mu.Unlock()
	if len(modemStub.contextErrs) != 1 {
		t.Fatalf("the modem was asked %d times, want 1", len(modemStub.contextErrs))
	}
	if err := modemStub.contextErrs[0]; err != nil {
		t.Fatalf("the modem was handed a context that had already ended: %v", err)
	}
	if left := modemStub.timeLeft[0]; left <= 0 || left > cellularSMSSendTimeout {
		t.Fatalf("the modem was given %v, want a limit of at most %v", left, cellularSMSSendTimeout)
	}
}

func TestSendSMSFallsBackToABackendThatOnlyTakesText(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	textOnly := &smsSendTextOnlyStub{}
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: textOnly})
	text := strings.Repeat("A", 200)

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "(10) 086", Text: text})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	if result.To != "10086" || result.PartsTotal != 2 || result.DeliveryState != "acked" {
		t.Fatalf("result = %+v", result)
	}
	if len(textOnly.to) != 1 || textOnly.to[0] != "10086" || textOnly.texts[0] != text {
		t.Fatalf("the backend was called %d times, for %q", len(textOnly.to), textOnly.to)
	}

	// Such a backend chooses the alphabet itself, so a forced one is refused
	// rather than silently ignored.
	_, err = pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "10086", Text: "synthetic", Encoding: smscodec.SMSEncodingUCS2})
	if err == nil || errors.Is(err, ErrSMSRequestInvalid) {
		t.Fatalf("forced alphabet on a text-only backend: error = %v, want a failure to send", err)
	}
	if len(textOnly.to) != 1 {
		t.Fatalf("the backend was called %d times, want the first call only", len(textOnly.to))
	}
}

func TestSendSMSHonoursAForcedAlphabet(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	modemStub := &smsSendModemStub{}
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1", Backend: modemStub})
	text := strings.Repeat("A", 100)

	plain, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "10086", Text: text})
	if err != nil {
		t.Fatalf("SendSMS: %v", err)
	}
	forced, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "10086", Text: text, Encoding: smscodec.SMSEncodingUCS2})
	if err != nil {
		t.Fatalf("SendSMS with a forced alphabet: %v", err)
	}
	// 100 characters fit one part in the GSM alphabet and need two in UCS-2.
	if plain.PartsTotal != 1 || forced.PartsTotal != 2 {
		t.Fatalf("parts: %d by default and %d forced to UCS-2, want 1 and 2", plain.PartsTotal, forced.PartsTotal)
	}
}

func TestSendSMSFailsOnADeviceWithoutAModemBackend(t *testing.T) {
	withoutIncomingSMSTestDB(t)
	pool := newSMSSendTestPool(t, &Worker{ID: "dev1"})

	result, err := pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: "dev1", To: "10086", Text: "synthetic"})
	if err == nil || errors.Is(err, ErrSMSRequestInvalid) || errors.Is(err, ErrSMSDeviceNotFound) {
		t.Fatalf("SendSMS error = %v, want a failure to send", err)
	}
	if result.Channel != SMSChannelCellular || result.DeliveryState != "failed" {
		t.Fatalf("result = %+v", result)
	}
}

func TestSMSChannelForFollowsTheWiFiCallingSession(t *testing.T) {
	pool, deviceID := newPoolSMSCallChain(t, runtimehost.State{SMSReady: true}, &smsSendIMSService{})

	if got := pool.SMSChannelFor(deviceID); got != SMSChannelIMS || got.Label() != "VoWiFi" {
		t.Fatalf("channel with a session = %q (%s)", got, got.Label())
	}
	pool.voWiFiRuntimeStore().SetInstance(deviceID, nil)
	if got := pool.SMSChannelFor(deviceID); got != SMSChannelCellular || got.Label() != "蜂窝" {
		t.Fatalf("channel without a session = %q (%s)", got, got.Label())
	}
}

func TestNormalizeSMSDeliveryStateUsesPathSpecificFailureFallback(t *testing.T) {
	tests := []struct {
		state    string
		fallback string
		want     string
	}{
		{state: "", fallback: "failed", want: "failed"},
		{state: "unknown", fallback: "failed", want: "failed"},
		{state: "partial_ack", fallback: "failed", want: "partial_ack"},
		{state: "ACKED", fallback: "failed", want: "acked"},
		{state: "DELIVERED", fallback: "failed", want: "delivered"},
		{state: " timeout ", fallback: "pending", want: "timeout"},
		{state: "", fallback: "", want: "pending"},
		{state: "unknown", fallback: "also unknown", want: "pending"},
	}
	for _, test := range tests {
		if got := NormalizeSMSDeliveryState(test.state, test.fallback); got != test.want {
			t.Fatalf("state=%q fallback=%q got=%q want=%q", test.state, test.fallback, got, test.want)
		}
	}
}
