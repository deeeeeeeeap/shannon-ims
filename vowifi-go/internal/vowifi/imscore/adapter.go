package imscore

import (
	"context"
	"strings"

	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// VoiceClientAdapter wraps the legacy voiceclient stack behind an imscore-like
// service surface. Upstream v1.1.2 uses the full ipsec3gpp imscore.Service;
// this adapter keeps the runtimecore integration path working until the
// private vowifi-go module is available.
type VoiceClientAdapter struct {
	deviceID  string
	traceID   string
	pcscf     string
	localAddr string
	inner     *voiceclient.Client
}

func NewVoiceClientAdapter(deviceID, traceID, localAddr, pcscf string, client *voiceclient.Client) *VoiceClientAdapter {
	return &VoiceClientAdapter{
		deviceID:  strings.TrimSpace(deviceID),
		traceID:   strings.TrimSpace(traceID),
		localAddr: strings.TrimSpace(localAddr),
		pcscf:     strings.TrimSpace(pcscf),
		inner:     client,
	}
}

func (a *VoiceClientAdapter) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if a == nil || a.inner == nil {
		return messaging.SendOutcome{}, voiceclientErr("IMS service not ready")
	}
	return a.inner.SendSMS(ctx, peer, content, parts)
}

func (a *VoiceClientAdapter) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	if a == nil || a.inner == nil {
		return nil, voiceclientErr("IMS service not ready")
	}
	return a.inner.SendUSSD(ctx, command)
}

func (a *VoiceClientAdapter) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	if a == nil || a.inner == nil {
		return nil, voiceclientErr("IMS service not ready")
	}
	return a.inner.ContinueUSSD(ctx, sessionID, input)
}

func (a *VoiceClientAdapter) CancelUSSD(ctx context.Context, sessionID string) error {
	if a == nil || a.inner == nil {
		return voiceclientErr("IMS service not ready")
	}
	return a.inner.CancelUSSD(ctx, sessionID)
}

func (a *VoiceClientAdapter) Close(ctx context.Context) error {
	if a == nil || a.inner == nil {
		return nil
	}
	return a.inner.Close(ctx)
}

// Status returns a map compatible with vohive API "imscore" observability.
func (a *VoiceClientAdapter) Status() map[string]interface{} {
	if a == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":            a.inner != nil,
		"device_id":          a.deviceID,
		"registered":         a.inner != nil,
		"reg_status":         "registered",
		"registrar":          a.pcscf,
		"local_addr":         a.localAddr,
		"sip_security_mode":  "voiceclient",
		"trace_id":           a.traceID,
		"signaling_ready":    a.inner != nil,
		"ipsec_installed":    false,
		"effective_security": "plain",
	}
}

type voiceclientAdapterError string

func (e voiceclientAdapterError) Error() string { return string(e) }

func voiceclientErr(msg string) error { return voiceclientAdapterError(msg) }