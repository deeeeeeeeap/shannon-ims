package voicehost

import (
	"context"

	"github.com/emiago/sipgo/sip"
)

const DefaultSimulateCallHoldSeconds = 15
const MaxSimulateCallHoldSeconds = 60

type SDPInfo struct {
	ConnectionIP string
	MediaPort    int
}

type SimulateCallRequest struct {
	Callee      string
	HoldSeconds int
	OnConnected func()
}

type SimulateCallResult struct {
	Success    bool
	DurationMs int
	Reason     string
}

func ParseSDP(body []byte) (*SDPInfo, error) {
	return &SDPInfo{ConnectionIP: "0.0.0.0", MediaPort: 0}, nil
}

type Gateway struct{}

func NewGateway() *Gateway { return &Gateway{} }

func (g *Gateway) Start(ctx context.Context) error    { return nil }
func (g *Gateway) Stop() error                         { return nil }
func (g *Gateway) SetClientAdapter(a interface{})     {}
func (g *Gateway) SetNotifier(n interface{})          {}
func (g *Gateway) GetAgent(deviceID string) interface{}    { return nil }
func (g *Gateway) DeviceStatus(deviceID string) map[string]interface{} { return nil }

func (g *Gateway) HandleClientInvite(deviceID string, req *sip.Request, tx sip.ServerTransaction) {}
func (g *Gateway) HandleClientBye(deviceID string, req *sip.Request, tx sip.ServerTransaction)   {}
func (g *Gateway) HandleClientCancel(deviceID string, req *sip.Request, tx sip.ServerTransaction) {}
func (g *Gateway) HandleClientPrack(deviceID string, req *sip.Request, tx sip.ServerTransaction) {}
func (g *Gateway) HandleClientAck(deviceID string, req *sip.Request, tx sip.ServerTransaction)   {}

func (g *Gateway) SimulateCall(ctx context.Context, deviceID string, req SimulateCallRequest) (SimulateCallResult, error) {
	return SimulateCallResult{Success: false, Reason: "not implemented"}, nil
}
