package swu

import (
	"context"
	"fmt"
	"sync"

	"github.com/1239t/vowifi-go/engine/swu/akabridge"
	"github.com/1239t/vowifi-go/engine/swu/charon"
	"github.com/1239t/vowifi-go/engine/swu/pcscfbridge"
)

// ManagerOptions configures a Manager.
type ManagerOptions struct {
	Charon charon.Options
}

// DefaultManagerOptions returns the options the package-level Dial()
// convenience function uses: charon.Options with only RunDir and
// DataplaneMode set explicitly, everything else at charon's own defaults
// (the AppArmor-safe socket/config paths — see engine/swu/charon's package
// doc comment for why those specific defaults matter).
func DefaultManagerOptions() ManagerOptions {
	return ManagerOptions{
		Charon: charon.Options{
			RunDir:        "/run/vohive-swu",
			DataplaneMode: charon.DataplaneModeUserspace,
		},
	}
}

// Manager owns the one shared charon process and akabridge listener that
// every device's SWu tunnel goes through, and brings up/tears down
// individual tunnels via Dial/Session.Close.
type Manager struct {
	sup         *charon.Supervisor
	bridge      *akabridge.Bridge
	pcscfBridge *pcscfbridge.Bridge

	mu              sync.Mutex
	started         bool
	bridgeStop      context.CancelFunc
	bridgeDone      chan struct{}
	pcscfStop       context.CancelFunc
	pcscfBridgeDone chan struct{}
}

// NewManager validates opts and prepares a Manager, but starts nothing —
// call Start before Dial.
func NewManager(opts ManagerOptions) (*Manager, error) {
	sup, err := charon.NewSupervisor(opts.Charon)
	if err != nil {
		return nil, err
	}
	return &Manager{
		sup:         sup,
		bridge:      akabridge.New(),
		pcscfBridge: pcscfbridge.New(),
	}, nil
}

// Start brings up the shared charon process and the akabridge listener.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return charon.ErrAlreadyRunning
	}

	if err := m.sup.Start(ctx); err != nil {
		return fmt.Errorf("swu: start charon: %w", err)
	}

	bridgeCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// The error here only matters once bridgeCtx is done on purpose
		// (Stop); this package has no logger of its own, and a bridge that
		// died unexpectedly surfaces naturally as failed AKA exchanges on
		// whatever Sessions are affected, not as a silent success.
		_ = m.bridge.ListenAndServe(bridgeCtx, m.sup.AKABridgeSocketPath())
	}()

	pcscfCtx, pcscfCancel := context.WithCancel(context.Background())
	pcscfDone := make(chan struct{})
	go func() {
		defer close(pcscfDone)
		// Same reasoning as the akabridge listener above: an unexpected
		// death here surfaces as Session.PCSCFAddr() never resolving, not
		// as a silent success.
		_ = m.pcscfBridge.ListenAndServe(pcscfCtx, m.sup.PCSCFBridgeSocketPath())
	}()

	m.bridgeStop = cancel
	m.bridgeDone = done
	m.pcscfStop = pcscfCancel
	m.pcscfBridgeDone = pcscfDone
	m.started = true
	return nil
}

// Stop tears down the akabridge listener and the charon process.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return charon.ErrNotRunning
	}
	stop := m.bridgeStop
	done := m.bridgeDone
	pcscfStop := m.pcscfStop
	pcscfDone := m.pcscfBridgeDone
	m.started = false
	m.bridgeStop = nil
	m.bridgeDone = nil
	m.pcscfStop = nil
	m.pcscfBridgeDone = nil
	m.mu.Unlock()

	stop()
	<-done
	pcscfStop()
	<-pcscfDone

	return m.sup.Stop(ctx)
}
