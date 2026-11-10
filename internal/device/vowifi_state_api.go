package device

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/1239t/vohive/pkg/smscodec"
	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// nextRPMR allocates RP-Message-Reference values for outgoing VoWiFi SMS
// parts. A single wrapping byte counter is sufficient: the delivery-report
// correlation path (messaging.DeliveryStore.MarkSMSDeliveryPartReport) also
// keys on deviceID and a time window, so this only needs to avoid
// collisions within that window, not be globally unique. There's no
// pre-existing allocator to reuse here -- SendSMS via SIP MESSAGE is new;
// vohive's legacy AT/QMI SMS path never called smscodec.BuildRPData.
var rpmrCounter uint32

func nextRPMR() byte {
	return byte(atomic.AddUint32(&rpmrCounter, 1))
}

func (p *Pool) GetVoWiFiApp() *runtimehost.Instance {
	return p.GetVoWiFiAppForDevice()
}

func (p *Pool) GetVoWiFiAppForDevice(deviceID ...string) *runtimehost.Instance {
	if len(deviceID) > 0 && deviceID[0] != "" {
		return p.voWiFiHost().Instance(deviceID[0])
	} else {
		for _, app := range p.voWiFiHost().Instances() {
			return app
		}
	}

	return nil
}

func (p *Pool) GetAllVoWiFiApps() map[string]*runtimehost.Instance {
	return p.voWiFiHost().Instances()
}

// SendVoWiFiSMSWithOptions encodes to/text into RP-DATA(SUBMIT) parts using
// vohive's own pkg/smscodec, then hands the already-encoded bytes to the
// vowifi-go IMS engine. That engine (vowifi-go/runtimehost) must not import
// vohive (the dependency runs the other way), so encoding responsibility
// -- TPDU construction, GSM7/UCS2 choice, RP-DATA framing, RP-MR allocation
// -- lives here, on vohive's side, per messaging.SMSPart's contract.
//
// It is the IMS leg on its own: it does not choose a channel and does not
// record a failed message. Callers that send a message for a user go through
// Pool.SendSMS.
func (p *Pool) SendVoWiFiSMSWithOptions(ctx context.Context, deviceID, to, text string, opts smscodec.SubmitOptions) (messaging.SendOutcome, error) {
	inst := p.voWiFiHost().Instance(deviceID)
	if inst == nil {
		return messaging.SendOutcome{}, fmt.Errorf("设备 %s 的 VoWiFi 未启动", deviceID)
	}

	worker := p.GetWorker(deviceID)
	if worker == nil {
		return messaging.SendOutcome{}, fmt.Errorf("设备 %s 不存在", deviceID)
	}

	// SMS over IMS always asks the service centre for a status report.
	opts.RequestStatusReport = true
	submission, err := smscodec.PrepareSubmission(to, text, opts)
	if err != nil {
		return messaging.SendOutcome{}, fmt.Errorf("编码 SMS TPDU 失败: %w", err)
	}
	return sendPreparedVoWiFiSMS(ctx, inst, worker, deviceID, submission, text)
}

// sendPreparedVoWiFiSMS frames a prepared message as RP-DATA, one per part,
// and hands the parts to the IMS engine. inst is the instance the caller
// decided to send on: looking it up again after the service centre query
// could find a session that has replaced it in the meantime.
func sendPreparedVoWiFiSMS(ctx context.Context, inst *runtimehost.Instance, worker *Worker, deviceID string, submission *smscodec.Submission, text string) (messaging.SendOutcome, error) {
	smscCtx, smscCancel := context.WithTimeout(ctx, 5*time.Second)
	smsc, err := worker.getSMSCWithContext(smscCtx)
	smscCancel()
	if err != nil {
		return messaging.SendOutcome{}, fmt.Errorf("获取 SMSC 失败: %w", err)
	}
	if smsc == "" {
		return messaging.SendOutcome{}, fmt.Errorf("设备 %s 未配置 SMSC，无法构建 RP-DATA", deviceID)
	}

	parts := make([]messaging.SMSPart, 0, submission.PartCount())
	for i := 0; i < submission.PartCount(); i++ {
		mr := nextRPMR()
		body, err := submission.RPData(i, mr, smsc)
		if err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("构建 RP-DATA 失败: %w", err)
		}
		parts = append(parts, messaging.SMSPart{
			ServiceCentre: smsc,
			RPMR:          mr,
			TPMR:          mr,
			Body:          body,
		})
	}

	return inst.SendSMS(ctx, submission.To(), text, parts)
}

func (p *Pool) IsVoWiFiActive(deviceID string) bool {
	return p.voWiFiHost().Active(deviceID)
}

// SendVoWiFiUSSD 通过 VoWiFi 发送 USSD 请求（首轮）。
func (p *Pool) SendVoWiFiUSSD(ctx context.Context, deviceID, command string) (*messaging.USSDResult, error) {
	if inst := p.voWiFiHost().Instance(deviceID); inst != nil {
		return inst.SendUSSD(ctx, command)
	}
	return nil, fmt.Errorf("设备 %s 的 VoWiFi 未启动", deviceID)
}

// ContinueVoWiFiUSSD 在已有 VoWiFi USSD 会话中发送后续输入。
func (p *Pool) ContinueVoWiFiUSSD(ctx context.Context, deviceID, sessionID, input string) (*messaging.USSDResult, error) {
	if inst := p.voWiFiHost().Instance(deviceID); inst != nil {
		return inst.ContinueUSSD(ctx, sessionID, input)
	}
	return nil, fmt.Errorf("设备 %s 的 VoWiFi 未启动", deviceID)
}

// CancelVoWiFiUSSD 取消 VoWiFi USSD 会话。
func (p *Pool) CancelVoWiFiUSSD(ctx context.Context, deviceID, sessionID string) error {
	if inst := p.voWiFiHost().Instance(deviceID); inst != nil {
		return inst.CancelUSSD(ctx, sessionID)
	}
	return fmt.Errorf("设备 %s 的 VoWiFi 未启动", deviceID)
}

func (p *Pool) GetVoWiFiStatus() (enabled bool, deviceID string, status string) {
	for devID, inst := range p.voWiFiHost().Instances() {
		if inst == nil {
			return true, devID, "VoWiFi: STOPPED"
		}
		return true, devID, inst.Status()
	}
	return false, "", "未初始化"
}

func (p *Pool) GetVoWiFiStatusAll() map[string]string {
	result := make(map[string]string)
	for devID, inst := range p.voWiFiHost().Instances() {
		result[devID] = inst.Status()
	}
	return result
}

func (p *Pool) GetVoWiFiObs(deviceID string) map[string]interface{} {
	if inst := p.voWiFiHost().Instance(deviceID); inst != nil {
		return inst.Obs()
	}
	return nil
}

func (p *Pool) GetVoWiFiRuntimeState(deviceID string) (runtimehost.State, bool) {
	return p.voWiFiHost().State(deviceID)
}

func (p *Pool) SubscribeVoWiFiState(deviceID string) (<-chan struct{}, func()) {
	return p.voWiFiHost().SubscribeState(deviceID)
}

func (p *Pool) recordVoWiFiStartupState(deviceID string, state runtimehost.State) {
	p.voWiFiHost().RecordStartupState(deviceID, state)
}

func (p *Pool) clearVoWiFiStartupState(deviceID string) {
	p.voWiFiHost().ClearStartupState(deviceID)
}

func (p *Pool) clearVoWiFiStartupStateAndBroadcast(deviceID string) {
	p.voWiFiHost().ClearStartupStateAndBroadcast(deviceID)
}

func (p *Pool) broadcastVoWiFiStateChange(deviceID string) {
	p.voWiFiHost().BroadcastState(deviceID)
}
