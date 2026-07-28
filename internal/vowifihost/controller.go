package vowifihost

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type LifecycleCommandKind int

const (
	LifecycleCommandEnable LifecycleCommandKind = iota + 1
	LifecycleCommandDisable
	LifecycleCommandRestart
	LifecycleCommandRecover
	LifecycleCommandSwitchBegin
	LifecycleCommandSwitchEnd
)

func (k LifecycleCommandKind) String() string {
	switch k {
	case LifecycleCommandEnable:
		return "enable"
	case LifecycleCommandDisable:
		return "disable"
	case LifecycleCommandRestart:
		return "restart"
	case LifecycleCommandRecover:
		return "recover"
	case LifecycleCommandSwitchBegin:
		return "switch_begin"
	case LifecycleCommandSwitchEnd:
		return "switch_end"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

type LifecycleCommand struct {
	DeviceID                 string
	Kind                     LifecycleCommandKind
	Reason                   string
	OverrideEPDG             string
	RestoreRadio             bool
	AllowSwitch              bool
	Generation               uint64
	desiredRecoverGeneration uint64
}

type LifecycleControllerOptions struct {
	Run func(context.Context, LifecycleCommand) error
}

// LifecycleController owns only per-device command serialization. RuntimeAttempt
// admission, freshness and cancellation are owned by Store.
type LifecycleController struct {
	mu                sync.Mutex
	devices           map[string]*deviceLifecycle
	run               func(context.Context, LifecycleCommand) error
	TestRun           func(context.Context, LifecycleCommand) error
	RecoverRunForTest func(context.Context, string, string, string) error
}

type deviceLifecycle struct {
	runMu sync.Mutex
}

func NewLifecycleController(options ...LifecycleControllerOptions) *LifecycleController {
	c := &LifecycleController{devices: make(map[string]*deviceLifecycle)}
	if len(options) > 0 {
		c.run = options[0].Run
	}
	return c
}

func (c *LifecycleController) SetRunForTest(fn func(context.Context, LifecycleCommand) error) {
	if c == nil {
		return
	}
	c.TestRun = fn
}

func (c *LifecycleController) SetRecoverRunForTest(fn func(context.Context, string, string, string) error) {
	if c == nil {
		return
	}
	c.RecoverRunForTest = fn
}

func (c *LifecycleController) Submit(ctx context.Context, cmd LifecycleCommand) error {
	if c == nil {
		return fmt.Errorf("vowifi lifecycle controller is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.DeviceID = strings.TrimSpace(cmd.DeviceID)
	if cmd.DeviceID == "" {
		return fmt.Errorf("vowifi lifecycle command device_id is empty")
	}
	if cmd.Kind == 0 {
		return fmt.Errorf("vowifi lifecycle command kind is empty")
	}

	lifecycle := c.device(cmd.DeviceID)
	lifecycle.runMu.Lock()
	defer lifecycle.runMu.Unlock()
	return c.runCommand(ctx, cmd)
}

func (c *LifecycleController) runCommand(ctx context.Context, cmd LifecycleCommand) error {
	if c.TestRun != nil {
		return c.TestRun(ctx, cmd)
	}
	if cmd.Kind == LifecycleCommandRecover && c.RecoverRunForTest != nil {
		return c.RecoverRunForTest(ctx, cmd.DeviceID, cmd.Reason, cmd.OverrideEPDG)
	}
	if c.run == nil {
		return fmt.Errorf("vowifi lifecycle controller run callback is nil")
	}
	return c.run(ctx, cmd)
}

func (c *LifecycleController) device(deviceID string) *deviceLifecycle {
	deviceID = strings.TrimSpace(deviceID)
	c.mu.Lock()
	defer c.mu.Unlock()
	if lifecycle := c.devices[deviceID]; lifecycle != nil {
		return lifecycle
	}
	lifecycle := &deviceLifecycle{}
	c.devices[deviceID] = lifecycle
	return lifecycle
}
