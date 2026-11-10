package device

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/modem"
	"github.com/1239t/vohive/internal/simulation/atsim"
)

// End-to-end tests without hardware. A simulated modem takes the place of the
// serial device; everything above it is the product: the AT manager, the
// device pool with its worker, the receive pipeline, the history database and
// the notifier interface. What the simulation cannot stand in for is how the
// operating system announces a modem (sysfs and udev), so the scan for
// hardware is replaced by a function that looks at the simulated modem.

const simulatedDeviceID = "sim-modem"

var simulatedDevicePortSeq atomic.Int64

// simulatedDevice is a device pool whose one device is a simulated modem,
// together with the history database and a notifier that records.
type simulatedDevice struct {
	t        *testing.T
	pool     *Pool
	sim      *atsim.Modem
	notifier *incomingSMSNotifierStub
	cfg      config.DeviceConfig
}

func startSimulatedDevice(t *testing.T, sim *atsim.Modem) *simulatedDevice {
	t.Helper()
	// Before the pool: a pool takes the database as it is when it is created.
	openIncomingSMSTestDB(t)
	port := fmt.Sprintf("sim://device-test-%d", simulatedDevicePortSeq.Add(1))
	t.Cleanup(modem.RegisterVirtualSerialPort(port, sim.Open))

	d := &simulatedDevice{
		t:        t,
		pool:     NewPool(&config.Config{}),
		sim:      sim,
		notifier: &incomingSMSNotifierStub{},
		cfg:      config.DeviceConfig{ID: simulatedDeviceID, DeviceBackend: "at", ATPort: port},
	}
	d.pool.SetNotifier(d.notifier)
	d.pool.rescanAndReconnectForTest = d.rescan
	t.Cleanup(func() { _ = d.pool.Shutdown() })

	if _, err := d.pool.AddWorkerFromConfig(d.cfg); err != nil {
		t.Fatalf("AddWorkerFromConfig() error = %v", err)
	}
	d.waitFor("the SIM identity to be read", 10*time.Second, func() bool { return d.worker().GetIMSI() != "" })
	return d
}

// rescan does what the scan for hardware does for one device: a worker whose
// modem no longer answers is removed, and a worker is started when the device
// is there.
func (d *simulatedDevice) rescan() error {
	if w := d.pool.GetWorker(simulatedDeviceID); w != nil {
		if w.Modem != nil && w.Modem.IsHealthy() {
			return nil
		}
		if err := d.pool.RemoveWorker(simulatedDeviceID); err != nil {
			return err
		}
	}
	_, err := d.pool.AddWorkerFromConfig(d.cfg)
	return err
}

func (d *simulatedDevice) worker() *Worker {
	d.t.Helper()
	w := d.pool.GetWorker(simulatedDeviceID)
	if w == nil {
		d.t.Fatal("the pool has no worker for the simulated modem")
	}
	return w
}

func (d *simulatedDevice) waitFor(what string, timeout time.Duration, done func() bool) {
	d.t.Helper()
	deadline := time.Now().Add(timeout)
	for !done() {
		if time.Now().After(deadline) {
			d.t.Fatalf("gave up after %v waiting for %s", timeout, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// deliver lets the network deliver a message to the modem, part by part.
func (d *simulatedDevice) deliver(from, text string, reference int) {
	d.t.Helper()
	for _, tpdu := range deliverTPDUs(d.t, from, text, reference) {
		if _, err := d.sim.DeliverSMS(tpdu); err != nil {
			d.t.Fatalf("DeliverSMS() error = %v", err)
		}
	}
}

// received returns sender and text of the received messages in the history,
// sorted.
func (d *simulatedDevice) received() []string {
	d.t.Helper()
	var out []string
	for _, row := range receivedSMS(d.t) {
		out = append(out, row.Sender+"|"+row.Content)
	}
	sort.Strings(out)
	return out
}

// waitForReceived waits until the history holds exactly the given messages.
func (d *simulatedDevice) waitForReceived(timeout time.Duration, want ...string) {
	d.t.Helper()
	sort.Strings(want)
	deadline := time.Now().Add(timeout)
	for {
		got := d.received()
		if strings.Join(got, "\n") == strings.Join(want, "\n") {
			return
		}
		if len(got) > len(want) || time.Now().After(deadline) {
			d.t.Fatalf("the history holds %d received messages %q, want %d %q", len(got), got, len(want), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// notified returns sender and text of the notifications, sorted.
func (d *simulatedDevice) notified() []string {
	var out []string
	for _, notice := range d.notifier.seen() {
		out = append(out, notice.Sender+"|"+notice.Content)
	}
	sort.Strings(out)
	return out
}

// sentHistory returns the messages the history records as sent from the device.
func (d *simulatedDevice) sentHistory() []db.SMS {
	d.t.Helper()
	var rows []db.SMS
	if err := db.DB.Where("type = ?", smsHistoryTypeSent).Order("id").Find(&rows).Error; err != nil {
		d.t.Fatalf("reading the history: %v", err)
	}
	return rows
}

func (d *simulatedDevice) modemIsEmpty() bool {
	return len(d.sim.StoredSMS("ME")) == 0
}

func TestSimulatedModemMessageIsStoredNotifiedAndRemovedFromTheModem(t *testing.T) {
	d := startSimulatedDevice(t, atsim.New(atsim.DefaultProfile()))

	d.deliver("+15555550142", "Your code is 482913", 1)
	d.waitForReceived(10*time.Second, "+15555550142|Your code is 482913")

	long := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 8)
	if parts := len(deliverTPDUs(t, "+15555550143", long, 21)); parts < 3 {
		t.Fatalf("the long message has %d parts, want at least 3", parts)
	}
	d.deliver("+15555550143", long, 21)
	d.waitForReceived(10*time.Second, "+15555550142|Your code is 482913", "+15555550143|"+long)

	d.waitFor("the messages to be deleted from the modem", 5*time.Second, d.modemIsEmpty)
	d.waitFor("both messages to be notified", 5*time.Second, func() bool { return len(d.notifier.seen()) == 2 })
	for _, notice := range d.notifier.seen() {
		if notice.DeviceID != simulatedDeviceID || notice.Source != incomingSMSViaCellular.source {
			t.Errorf("notification %+v, want the simulated device and the cellular channel", notice)
		}
	}
	for _, row := range receivedSMS(t) {
		if row.IMSI != incomingSMSTestIMSI {
			t.Errorf("the message was stored for the subscriber %q, want %q", row.IMSI, incomingSMSTestIMSI)
		}
	}
}

func TestSimulatedModemLongMessageWhosePartsArriveOutOfOrderIsPutTogether(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)

	long := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 8)
	parts := deliverTPDUs(t, "+15555550143", long, 33)
	if len(parts) < 3 {
		t.Fatalf("the long message has %d parts, want at least 3", len(parts))
	}
	// The last part comes first, then another message, then the remaining
	// parts from the back.
	for i := len(parts) - 1; i >= 0; i-- {
		if _, err := sim.DeliverSMS(parts[i]); err != nil {
			t.Fatalf("DeliverSMS() error = %v", err)
		}
		if i == len(parts)-1 {
			d.deliver("+15555550142", "in between", 1)
		}
	}

	d.waitForReceived(10*time.Second, "+15555550142|in between", "+15555550143|"+long)
	d.waitFor("the parts to be deleted from the modem", 5*time.Second, d.modemIsEmpty)
	d.waitFor("both messages to be notified", 5*time.Second, func() bool { return len(d.notifier.seen()) >= 2 })
	if got := d.notified(); len(got) != 2 {
		t.Errorf("%d notifications %q, want one for each message", len(got), got)
	}
}

func TestSimulatedModemMessagesThatArrivedWhileTheHostWasDownAreCollected(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	want := []string{}
	for i := 1; i <= 5; i++ {
		text := fmt.Sprintf("waiting message %d", i)
		if _, err := sim.StoreSMS("ME", atsim.ReceivedUnread, deliverTPDU(t, "+15555550142", text)); err != nil {
			t.Fatalf("StoreSMS() error = %v", err)
		}
		want = append(want, "+15555550142|"+text)
	}
	d := startSimulatedDevice(t, sim)

	// Nothing announces these messages. The worker reads the storage shortly
	// after it has started and then once a minute; this is that read.
	d.worker().pollStoredSMS("startup")

	d.waitForReceived(10*time.Second, want...)
	if !d.modemIsEmpty() {
		t.Errorf("%d messages were left in the modem", len(sim.StoredSMS("ME")))
	}

	// A second read finds nothing and repeats nothing.
	d.worker().pollStoredSMS("poll")
	if got := d.notified(); len(got) != len(want) {
		t.Errorf("%d notifications, want %d", len(got), len(want))
	}
}

func TestSimulatedModemBurstOfMessagesIsStoredExactlyOnce(t *testing.T) {
	d := startSimulatedDevice(t, atsim.New(atsim.DefaultProfile()))
	w := d.worker()

	// The control channel is busy with status queries while the messages arrive.
	stop := make(chan struct{})
	var busy sync.WaitGroup
	busy.Add(1)
	go func() {
		defer busy.Done()
		for {
			select {
			case <-stop:
				return
			default:
				w.Modem.RefreshStatus(nil, nil)
			}
		}
	}()

	var want []string
	for i := 1; i <= 40; i++ {
		text := fmt.Sprintf("burst message %d", i)
		d.deliver("+15555550142", text, 1)
		want = append(want, "+15555550142|"+text)
	}
	for i := 1; i <= 3; i++ {
		text := fmt.Sprintf("long burst message %d: ", i) + strings.Repeat("The quick brown fox jumps over the lazy dog. ", 8)
		d.deliver("+15555550143", text, 40+i)
		want = append(want, "+15555550143|"+text)
	}

	d.waitForReceived(60*time.Second, want...)
	close(stop)
	busy.Wait()

	d.waitFor("the messages to be deleted from the modem", 10*time.Second, d.modemIsEmpty)
	d.waitFor("every message to be notified", 5*time.Second, func() bool { return len(d.notifier.seen()) >= len(want) })
	got := d.notified()
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%d notifications, want each of the %d messages once", len(got), len(want))
	}
	if !w.Modem.IsHealthy() {
		t.Error("the modem manager is not healthy after the burst")
	}
}

func TestSimulatedModemMessageAnnouncedInTheMiddleOfAnAnswerIsNotLost(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)

	// The message is in the storage, and its announcement reaches the host
	// between the lines of the answer to another command.
	index, err := sim.StoreSMS("ME", atsim.ReceivedUnread, deliverTPDU(t, "+15555550142", "in between"))
	if err != nil {
		t.Fatalf("StoreSMS() error = %v", err)
	}
	sim.AddRule(atsim.Rule{Prefix: "AT+CSQ", Times: 1, URC: fmt.Sprintf(`+CMTI: "ME",%d`, index)})
	answer, err := d.worker().Modem.ExecuteAT("AT+CSQ", 2*time.Second)
	if err != nil || answer != "+CSQ: 20,99" {
		t.Fatalf("ExecuteAT() = %q, %v, want only the answer to the command", answer, err)
	}

	d.waitForReceived(10*time.Second, "+15555550142|in between")
	d.waitFor("the message to be deleted from the modem", 5*time.Second, d.modemIsEmpty)
}

func TestSimulatedModemSendsMessagesThroughThePool(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)

	result, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello"})
	if err != nil {
		t.Fatalf("SendSMS() error = %v", err)
	}
	if result.Channel != SMSChannelCellular || result.PartsTotal != 1 || result.DeliveryState != db.SMSDeliveryStateAcked || result.To != "+15555550142" {
		t.Errorf("SendSMS() = %+v", result)
	}

	long := strings.Repeat("0123456789", 40)
	result, err = d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: long})
	if err != nil {
		t.Fatalf("SendSMS() of a long text error = %v", err)
	}
	if result.PartsTotal < 3 || result.DeliveryState != db.SMSDeliveryStateAcked {
		t.Errorf("SendSMS() of a long text = %+v", result)
	}
	if got := len(sim.SentSMS()); got != 1+result.PartsTotal {
		t.Errorf("the modem sent %d messages, want %d", got, 1+result.PartsTotal)
	}

	rows := d.sentHistory()
	if len(rows) != 2 {
		t.Fatalf("the history holds %d sent messages, want 2", len(rows))
	}
	for i, text := range []string{"hello", long} {
		row := rows[i]
		if row.Content != text || row.Recipient != "+15555550142" || row.Status != smsHistoryStatusSent || row.IMSI != incomingSMSTestIMSI {
			t.Errorf("history row %d = recipient %q status %d subscriber %q with %d characters", i+1, row.Recipient, row.Status, row.IMSI, len(row.Content))
		}
	}
}

func TestSimulatedModemSendFailuresAreReportedAndRecorded(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)
	request := SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello"}

	// The network refuses the message.
	sim.AddRule(atsim.Rule{Prefix: "AT+CMGS", Times: 1, Result: "+CMS ERROR: 38"})
	result, err := d.pool.SendSMS(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "+CMS ERROR: 38") {
		t.Fatalf("SendSMS() error = %v, want the refusal of the network", err)
	}
	if result.DeliveryState != db.SMSDeliveryStateFailed || result.PartsTotal != 1 {
		t.Errorf("SendSMS() = %+v", result)
	}

	// The modem has no service.
	sim.SetRegistration(atsim.Searching)
	if _, err := d.pool.SendSMS(context.Background(), request); err == nil || !strings.Contains(err.Error(), "+CMS ERROR: 331") {
		t.Fatalf("SendSMS() without service error = %v", err)
	}
	sim.SetRegistration(atsim.RegisteredHome)

	// A destination that cannot be dialled is refused before the modem is asked.
	before := sim.Count("AT+CMGS")
	if _, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "not a number", Text: "hello"}); !errors.Is(err, ErrSMSRequestInvalid) {
		t.Fatalf("SendSMS() to an unusable destination error = %v, want ErrSMSRequestInvalid", err)
	}
	if got := sim.Count("AT+CMGS"); got != before {
		t.Errorf("the modem was asked to send %d times for a request that is invalid", got-before)
	}

	// The device still sends.
	if _, err := d.pool.SendSMS(context.Background(), request); err != nil {
		t.Fatalf("SendSMS() after the failures error = %v", err)
	}

	var statuses []int
	for _, row := range d.sentHistory() {
		statuses = append(statuses, row.Status)
	}
	want := []int{smsHistoryStatusFailed, smsHistoryStatusFailed, smsHistoryStatusSent}
	if fmt.Sprint(statuses) != fmt.Sprint(want) {
		t.Errorf("history statuses = %v, want %v: one row per message that reached the modem", statuses, want)
	}
	if got := len(sim.SentSMS()); got != 1 {
		t.Errorf("the modem sent %d messages, want 1", got)
	}
}

func TestSimulatedModemThatIsUnpluggedIsTakenOverAgainWhenItIsBack(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)
	before := d.worker()

	d.deliver("+15555550142", "before the cable was pulled", 1)
	d.waitForReceived(10*time.Second, "+15555550142|before the cable was pulled")

	sim.Unplug()
	d.waitFor("the pool to notice that the modem is gone", 10*time.Second, func() bool {
		w := d.pool.GetWorker(simulatedDeviceID)
		return w == nil || !w.Modem.IsHealthy()
	})
	if _, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello"}); err == nil {
		t.Error("SendSMS() succeeded although the modem is unplugged")
	}

	// The modem is plugged in again, and a message reaches it before the
	// host has taken it over: nothing announces that one.
	sim.Replug()
	if _, err := sim.StoreSMS("ME", atsim.ReceivedUnread, deliverTPDU(t, "+15555550142", "while the host was away")); err != nil {
		t.Fatalf("StoreSMS() error = %v", err)
	}

	d.waitFor("the pool to take the modem over again", 30*time.Second, func() bool {
		w := d.pool.GetWorker(simulatedDeviceID)
		return w != nil && w != before && w.Modem.IsHealthy() && w.GetIMSI() != ""
	})

	d.deliver("+15555550142", "after the modem came back", 1)
	d.waitForReceived(10*time.Second,
		"+15555550142|before the cable was pulled",
		"+15555550142|after the modem came back")

	// The read that follows a start collects what was not announced.
	d.worker().pollStoredSMS("startup")
	d.waitForReceived(10*time.Second,
		"+15555550142|before the cable was pulled",
		"+15555550142|after the modem came back",
		"+15555550142|while the host was away")

	if _, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello again"}); err != nil {
		t.Errorf("SendSMS() after the modem came back error = %v", err)
	}
}

func TestSimulatedModemThatRestartsIsTakenOverAgain(t *testing.T) {
	profile := atsim.DefaultProfile()
	profile.BootTime = 500 * time.Millisecond
	sim := atsim.New(profile)
	d := startSimulatedDevice(t, sim)
	before := d.worker()

	// The module restarts on its own: its port disappears and comes back
	// after the boot time.
	sim.Restart()
	d.waitFor("the pool to take the modem over again", 30*time.Second, func() bool {
		w := d.pool.GetWorker(simulatedDeviceID)
		return w != nil && w != before && w.Modem.IsHealthy() && w.GetIMSI() != ""
	})

	// The restart reset the settings of the module; the new worker has set
	// it up again, so a message is announced and read.
	if settings := sim.Settings(); settings.Echo || settings.NewMessageIndication != "2,1,0,0,0" {
		t.Fatalf("the modem was not set up again after its restart: %+v", settings)
	}
	d.deliver("+15555550142", "after the restart", 1)
	d.waitForReceived(10*time.Second, "+15555550142|after the restart")
}

func TestSimulatedModemThatHangsIsReplacedAndWorksAgain(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)
	before := d.worker()

	sim.SetSilent(true)
	if _, err := before.Modem.ExecuteAT("AT+CSQ", 300*time.Millisecond); err == nil {
		t.Fatal("a command succeeded on a modem that does not answer")
	}
	if before.Modem.IsHealthy() {
		t.Fatal("the modem manager still counts as healthy after a command without an answer")
	}

	// A message cannot be sent, and the caller learns that quickly instead
	// of waiting for the modem.
	start := time.Now()
	if _, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello"}); err == nil {
		t.Error("SendSMS() succeeded on a modem that does not answer")
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("SendSMS() took %v to fail on a modem that is known not to answer", waited)
	}

	// The modem recovers. The periodic health check of the pool finds the
	// device unhealthy and starts the scan that reconnects it. That scan
	// looks for hardware, so its stand-in for the simulated modem runs here.
	sim.SetSilent(false)
	if err := d.rescan(); err != nil {
		t.Fatalf("replacing the worker: %v", err)
	}
	after := d.worker()
	if after == before || !after.Modem.IsHealthy() {
		t.Fatal("the worker of the modem that hung was not replaced by a healthy one")
	}
	d.waitFor("the SIM identity to be read", 10*time.Second, func() bool { return after.GetIMSI() != "" })

	d.deliver("+15555550142", "after the hang", 1)
	d.waitForReceived(10*time.Second, "+15555550142|after the hang")
	if _, err := d.pool.SendSMS(context.Background(), SMSSendRequest{DeviceID: simulatedDeviceID, To: "+15555550142", Text: "hello"}); err != nil {
		t.Errorf("SendSMS() after the modem recovered error = %v", err)
	}
}

func TestSimulatedModemStatusPollsAreNotTakenForAModemThatJustBecameReady(t *testing.T) {
	sim := atsim.New(atsim.DefaultProfile())
	d := startSimulatedDevice(t, sim)
	w := d.worker()
	// The pool reacts to a modem that reports itself ready by waking the
	// recovery of VoWiFi for the device. The wake-up stays pending for half a
	// second before it is handled.
	wakeUpPending := func() bool {
		d.pool.deviceEventWakeMu.Lock()
		defer d.pool.deviceEventWakeMu.Unlock()
		return d.pool.deviceEventWakeups[simulatedDeviceID] != nil
	}

	// Starting up found the SIM ready for the first time, which is news.
	time.Sleep(100 * time.Millisecond)
	d.waitFor("the wake-up from the start to be handled", 5*time.Second, func() bool { return !wakeUpPending() })

	// The status query that the pool repeats for a device in AT mode finds
	// the SIM ready, as before. That is not news.
	for i := 0; i < 5; i++ {
		w.Modem.RefreshStatus(nil, nil)
	}
	if got := sim.Count("AT+CPIN?"); got < 5 {
		t.Fatalf("the SIM was queried %d times, want the status query to ask every time", got)
	}
	time.Sleep(200 * time.Millisecond)
	if wakeUpPending() {
		t.Fatal("an answer to the status query was taken for the modem reporting itself ready")
	}

	// The modem reporting itself ready is news every time.
	sim.URC("RDY")
	d.waitFor("the report of the modem to wake the recovery of VoWiFi", 3*time.Second, wakeUpPending)
}
