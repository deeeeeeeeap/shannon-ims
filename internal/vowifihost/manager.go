package vowifihost

import (
	"context"
	"fmt"
	"strings"

	"github.com/1239t/vowifi-go/runtimehost"
	"github.com/1239t/vowifi-go/runtimehost/eventhost"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voicehost"
)

type Manager struct {
	runtimeStore  *Store
	lifecycle     *LifecycleController
	recoverClock  desiredRecoverClock
	lifecycleRun  func(context.Context, LifecycleCommand) error
	lifecycleTest func(context.Context, LifecycleCommand) error
	recoverTest   func(context.Context, string, string, string) error
	runtimeStart  runtimeStartFunc
	adapter       Adapter
	voiceGateway  *voicehost.Gateway
	deliveryStore messaging.DeliveryStore
	dispatcher    eventhost.Dispatcher
}

func NewManager() *Manager {
	m := &Manager{
		runtimeStore: NewRuntimeStore(),
		recoverClock: realDesiredRecoverClock{},
	}
	m.lifecycle = NewLifecycleController(LifecycleControllerOptions{
		Run: m.runAdmittedLifecycleCommand,
	})
	return m
}

func (m *Manager) RuntimeStore() *Store {
	if m == nil || m.runtimeStore == nil {
		return NewRuntimeStore()
	}
	return m.runtimeStore
}

func (m *Manager) SubscribeState(deviceID string) (<-chan struct{}, func()) {
	return m.RuntimeStore().Subscribe(deviceID)
}

func (m *Manager) BroadcastState(deviceID string) {
	m.RuntimeStore().Broadcast(deviceID)
}

func (m *Manager) SubscriberCount(deviceID string) int {
	return m.RuntimeStore().SubscriberCount(deviceID)
}

func (m *Manager) RecordStartupState(deviceID string, state runtimehost.State) bool {
	return m.RuntimeStore().RecordStartupState(deviceID, state)
}

func (m *Manager) publishRuntimeState(deviceID string, epoch uint64, inst *runtimehost.Instance, state runtimehost.State) bool {
	return m.RuntimeStore().publishRuntimeState(deviceID, epoch, inst, state)
}

func (m *Manager) ClearStartupState(deviceID string) bool {
	return m.RuntimeStore().ClearStartupState(deviceID)
}

func (m *Manager) ConfigureRuntimeDependencies(vg *voicehost.Gateway, ds messaging.DeliveryStore, ed eventhost.Dispatcher) {
	if m == nil {
		return
	}
	m.voiceGateway = vg
	m.deliveryStore = ds
	m.dispatcher = ed
}

func (m *Manager) ClearStartupStateAndBroadcast(deviceID string) {
	m.ClearStartupState(deviceID)
}

func (m *Manager) ConfigureLifecycle(options LifecycleControllerOptions) {
	if m == nil {
		return
	}
	m.lifecycleRun = options.Run
	m.lifecycle = NewLifecycleController(LifecycleControllerOptions{Run: m.runAdmittedLifecycleCommand})
}

func (m *Manager) SubmitLifecycle(ctx context.Context, cmd LifecycleCommand) error {
	if m == nil {
		return fmt.Errorf("vowifi host manager is nil")
	}
	cmd.DeviceID = strings.TrimSpace(cmd.DeviceID)
	if cmd.DeviceID == "" {
		return fmt.Errorf("vowifi lifecycle command device_id is empty")
	}
	if cmd.Kind == 0 {
		return fmt.Errorf("vowifi lifecycle command kind is empty")
	}

	var accepted bool
	if cmd.Kind == LifecycleCommandDisable || cmd.Kind == LifecycleCommandRestart || cmd.Kind == LifecycleCommandSwitchBegin {
		generation, cancel := m.RuntimeStore().preemptLifecycle(cmd.DeviceID)
		cmd.Generation = generation
		accepted = generation != 0
		if cancel != nil {
			cancel()
		}
	} else {
		cmd.Generation, accepted = m.RuntimeStore().admitLifecycle(cmd.DeviceID, cmd.Kind)
	}
	if !accepted {
		return nil
	}
	return m.lifecycleController().Submit(ctx, cmd)
}

func (m *Manager) SetLifecycleRunForTest(fn func(context.Context, LifecycleCommand) error) {
	if m != nil {
		m.lifecycleTest = fn
	}
}

func (m *Manager) SetLifecycleRecoverRunForTest(fn func(context.Context, string, string, string) error) {
	if m != nil {
		m.recoverTest = fn
	}
}

func (m *Manager) LifecycleControllerForTest() *LifecycleController {
	return m.lifecycleController()
}

func (m *Manager) lifecycleController() *LifecycleController {
	if m == nil || m.lifecycle == nil {
		if m == nil {
			return NewLifecycleController()
		}
		m.ConfigureLifecycle(LifecycleControllerOptions{})
	}
	return m.lifecycle
}
