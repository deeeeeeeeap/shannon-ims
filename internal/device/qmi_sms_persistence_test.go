package device

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/db"
	qmicore "github.com/1239t/vohive/internal/qmi"
	"github.com/1239t/vohive/pkg/smscodec"
	qmimanager "github.com/iniwex5/quectel-qmi-go/pkg/manager"
	"github.com/iniwex5/quectel-qmi-go/pkg/qmi"
)

func newPersistentQMITestWorker(t *testing.T, core *qmiSMSCoreStub) *Worker {
	t.Helper()
	previous := db.DB
	if err := db.Init(filepath.Join(t.TempDir(), "fixture.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection, _ := db.DB.DB(); _ = connection.Close(); db.DB = previous })
	return &Worker{ID: "fixture-device", Pool: NewPool(nil), qmiSMS: core,
		Backend: &workerPhoneBackendStub{imsi: "fixture-sim"}, reassembler: smscodec.NewReassembler()}
}

func syntheticQMIRawPDU() []byte {
	return []byte{0, 5, 0x81, 0x55, 0x05, 0xf1, 0, 8, 0x62, 0x11, 0x30, 0x01, 0, 0, 0, 4, 0, 'H', 0, 'i'}
}

func TestQMIRawStorageFailureRejectsAndRetryDeduplicates(t *testing.T) {
	core := &qmiSMSCoreStub{}
	worker := newPersistentQMITestWorker(t, core)
	notifier := &countingVoWiFiNotifier{}
	worker.Pool.SetNotifier(notifier)
	info := qmicore.RawSMSIndication{PDU: syntheticQMIRawPDU(), AckRequired: true, TransactionID: 7, Format: 6}
	if err := db.DB.Exec("CREATE TRIGGER fail_inbox BEFORE INSERT ON sms BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	worker.handleNewSMSRawQMI(info)
	if len(core.ackCalls) != 0 || len(core.ackRejects) != 1 || notifier.smsCount != 0 {
		t.Fatal("storage failure was acknowledged or notified as received")
	}
	if err := db.DB.Exec("DROP TRIGGER fail_inbox").Error; err != nil {
		t.Fatal(err)
	}
	worker.handleNewSMSRawQMI(info)
	worker.handleNewSMSRawQMI(info)
	rows, err := db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || len(core.ackCalls) != 2 || notifier.smsCount != 1 {
		t.Fatal("raw SMS retry was lost or duplicated")
	}
}

func TestQMIMultipartSurvivesWorkerReplacement(t *testing.T) {
	core := &qmiSMSCoreStub{readResults: map[string]*qmimanager.DecodedSMS{
		"0:1": {Sender: "55501", Message: "A", Timestamp: time.Unix(1700000000, 0), IsConcat: true, ConcatRef: 7, ConcatSeq: 1, ConcatTotal: 2},
		"0:2": {Sender: "55501", Message: "B", Timestamp: time.Unix(1700000001, 0), IsConcat: true, ConcatRef: 7, ConcatSeq: 2, ConcatTotal: 2},
	}}
	worker := newPersistentQMITestWorker(t, core)
	notifier := &countingVoWiFiNotifier{}
	worker.Pool.SetNotifier(notifier)
	if err := worker.handleNewSMSQMI(0, 1); err != nil {
		t.Fatal(err)
	}
	if len(core.deleteCalls) != 1 || notifier.smsCount != 0 {
		t.Fatal("durable incomplete part was not removed or was notified too early")
	}
	worker = &Worker{ID: worker.ID, Pool: worker.Pool, Backend: worker.Backend, qmiSMS: core}
	if err := worker.handleNewSMSQMI(0, 2); err != nil {
		t.Fatal(err)
	}
	rows, err := db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || rows[0].Content != "AB" || notifier.smsCount != 1 {
		t.Fatal("acknowledged multipart data was lost on worker replacement")
	}
}

func TestQMIStorageFailureRetainsAndRetriesReadSMS(t *testing.T) {
	core := &qmiSMSCoreStub{readResults: map[string]*qmimanager.DecodedSMS{
		"0:7": {Sender: "55501", Message: "fixture", Timestamp: time.Now()},
	}}
	worker := newPersistentQMITestWorker(t, core)
	if err := db.DB.Exec("CREATE TRIGGER fail_inbox BEFORE INSERT ON sms BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	worker.handleNewSMSQMI(0, 7)
	if len(core.deleteCalls) != 0 {
		t.Fatal("modem copy deleted after failed persistence")
	}
	if err := db.DB.Exec("DROP TRIGGER fail_inbox").Error; err != nil {
		t.Fatal(err)
	}
	core.listByStorage = map[uint8][]struct {
		Index uint32
		Tag   qmi.MessageTagType
	}{0: {{Index: 7, Tag: qmi.TagTypeMTRead}}}
	if err := worker.CheckAllSMSQMI(); err != nil {
		t.Fatal(err)
	}
	rows, err := db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 || len(core.deleteCalls) != 1 {
		t.Fatal("read SMS was not saved before retry cleanup")
	}
	if err := worker.CheckAllSMSQMI(); err != nil {
		t.Fatal(err)
	}
	rows, err = db.GetSMSByIMSI("fixture-sim", 10)
	if err != nil || len(rows) != 1 {
		t.Fatal("delete retry duplicated inbox entry")
	}
}
