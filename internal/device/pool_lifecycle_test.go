package device

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/config"
)

func TestPoolContextFollowsApplicationLifecycle(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	pool := NewPoolWithContext(parent, &config.Config{})
	cancelParent()

	select {
	case <-pool.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("Pool context did not follow application cancellation")
	}
}

func TestPoolShutdownContextJoinsOwnedBackgroundTask(t *testing.T) {
	pool := NewPoolWithContext(context.Background(), &config.Config{})
	started := make(chan struct{})
	exited := make(chan struct{})
	if !pool.startOwnedBackground(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(exited)
	}) {
		t.Fatal("startOwnedBackground() rejected task before shutdown")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("owned Pool task did not start")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	if err := pool.ShutdownContext(shutdownCtx); err != nil {
		t.Fatalf("ShutdownContext() error=%v", err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("ShutdownContext() returned before owned Pool task exited")
	}
	if pool.startOwnedBackground(func(context.Context) {}) {
		t.Fatal("startOwnedBackground() accepted task after shutdown")
	}
}

func TestPoolShutdownContextJoinsDataConnectedCallback(t *testing.T) {
	pool := NewPoolWithContext(context.Background(), &config.Config{})
	started := make(chan struct{})
	release := make(chan struct{})
	pool.OnDataConnected(func(string) {
		close(started)
		<-release
	})
	pool.notifyDataConnected("synthetic-device")
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("data-connected callback did not start")
	}

	shortCtx, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelShort()
	if err := pool.ShutdownContext(shortCtx); err != context.DeadlineExceeded {
		t.Fatalf("ShutdownContext() error=%v, want deadline while callback is active", err)
	}

	close(release)
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), time.Second)
	defer cancelJoin()
	if err := pool.ShutdownContext(joinCtx); err != nil {
		t.Fatalf("ShutdownContext() after callback release error=%v", err)
	}
}

func TestSuppressQMIUnhealthyEvictionDuringLifecycleRecovery(t *testing.T) {
	pool := NewPool(&config.Config{})
	worker := &Worker{
		ID: "dev1",
		Config: config.DeviceConfig{
			ID:            "dev1",
			DeviceBackend: backend.BackendQMI,
			ControlDevice: "/dev/cdc-wdm0",
		},
		Backend: &workerStatusBackendStub{mode: backend.BackendQMI, opModeErr: errBackendUnavailable{}},
	}
	pool.workers["dev1"] = worker
	pool.lifecycle.BeginRecovery("dev1", LifecyclePhaseQMIStarting, "modem_reboot", qmiLifecycleRecoveryTTL)

	suppressed, reason := pool.suppressQMIUnhealthyEviction(worker)
	if !suppressed {
		t.Fatal("expected lifecycle recovery to suppress eviction")
	}
	if !strings.Contains(reason, "lifecycle_qmi_starting") {
		t.Fatalf("reason=%q want contains lifecycle_qmi_starting", reason)
	}
}

func TestSuppressQMIUnhealthyEvictionAfterLifecycleDeadline(t *testing.T) {
	pool := NewPool(&config.Config{})
	worker := &Worker{
		ID: "dev1",
		Config: config.DeviceConfig{
			ID:            "dev1",
			DeviceBackend: backend.BackendQMI,
			ControlDevice: "/dev/cdc-wdm0",
		},
		Backend: &workerStatusBackendStub{mode: backend.BackendQMI, opModeErr: errBackendUnavailable{}},
	}
	now := time.Now().Add(-2 * qmiLifecycleRecoveryTTL)
	pool.lifecycle.BeginRecoveryAt("dev1", LifecyclePhaseRecovering, "modem_reboot", now, time.Second)

	suppressed, reason := pool.suppressQMIUnhealthyEviction(worker)
	if suppressed {
		t.Fatalf("suppressed=true want false reason=%q", reason)
	}
}

type errBackendUnavailable struct{}

func (errBackendUnavailable) Error() string { return "backend unavailable" }
