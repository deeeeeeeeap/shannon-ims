package server

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// InstanceConfig 表示代理实例运行参数。
type InstanceConfig struct {
	ID          string
	Mode        string
	Enabled     bool
	ListenAddr  string
	ListenPort  int
	Interface   string
	AuthEnabled bool
	Username    string
	Password    string
}

// InstanceStatus 表示代理实例状态。
type InstanceStatus struct {
	ID          string    `json:"id"`
	Mode        string    `json:"mode,omitempty"`
	Running     bool      `json:"running"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	LastExitAt  time.Time `json:"last_exit_at,omitempty"`
	LastExitOK  bool      `json:"last_exit_ok,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	ListenAddr  string    `json:"listen_addr,omitempty"`
	ListenPort  int       `json:"listen_port,omitempty"`
	Interface   string    `json:"interface,omitempty"`
	AuthEnabled bool      `json:"auth_enabled,omitempty"`
}

type TrafficCounters struct {
	Uplink   int64
	Downlink int64
}

type instanceRuntime struct {
	cfg        InstanceConfig
	srv        *Server
	startedAt  time.Time
	lastExitAt time.Time
	lastExitOK bool
	lastError  string
}

// Manager 管理多个代理实例生命周期。
type Manager struct {
	mu          sync.Mutex
	instances   map[string]*instanceRuntime
	configByID  map[string]InstanceConfig
	lastTraffic map[string][2]int64 // id -> [rx, tx]
}

func NewManager() *Manager {
	return &Manager{
		instances:   make(map[string]*instanceRuntime),
		configByID:  make(map[string]InstanceConfig),
		lastTraffic: make(map[string][2]int64),
	}
}

func (m *Manager) ApplyConfigs(ctx context.Context, configs []InstanceConfig) error {
	next := make(map[string]InstanceConfig, len(configs))
	for _, c := range configs {
		if c.ID == "" {
			return errors.New("代理实例缺少 id")
		}
		c.Mode = normalizeMode(c.Mode)
		next[c.ID] = c
	}

	var stopIDs []string
	var startIDs []string
	var restartIDs []string
	var deleteRuntimeIDs []string

	m.mu.Lock()
	prev := m.configByID
	m.configByID = next

	for id := range prev {
		if _, stillExists := next[id]; stillExists {
			continue
		}
		rt := m.instances[id]
		if rt != nil && rt.srv != nil {
			stopIDs = append(stopIDs, id)
		}
		deleteRuntimeIDs = append(deleteRuntimeIDs, id)
	}

	for id, newCfg := range next {
		rt := m.instances[id]
		running := rt != nil && rt.srv != nil

		if !newCfg.Enabled {
			if running {
				stopIDs = append(stopIDs, id)
			}
			continue
		}

		if !running {
			startIDs = append(startIDs, id)
			continue
		}

		if prevCfg, ok := prev[id]; ok {
			if !instanceConfigEqual(prevCfg, newCfg) {
				restartIDs = append(restartIDs, id)
			}
		} else {
			restartIDs = append(restartIDs, id)
		}
	}
	m.mu.Unlock()

	var errs []error
	for _, id := range stopIDs {
		if err := m.Stop(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}

	m.mu.Lock()
	for _, id := range deleteRuntimeIDs {
		delete(m.instances, id)
		delete(m.lastTraffic, id)
	}
	m.mu.Unlock()

	for _, id := range restartIDs {
		if err := m.Restart(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	for _, id := range startIDs {
		if err := m.Start(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *Manager) Start(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	m.mu.Lock()
	cfg, ok := m.configByID[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("代理实例不存在: %s", id)
	}
	rt := m.instances[id]
	if rt != nil && rt.srv != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	srv, err := New(id, cfg.Mode, cfg.ListenAddr, cfg.ListenPort, cfg.Interface, cfg.AuthEnabled, cfg.Username, cfg.Password)
	if err != nil {
		m.recordError(id, err)
		return err
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-errCh:
			m.recordError(id, err)
			return err
		case <-ctx.Done():
			_ = srv.Shutdown()
			return ctx.Err()
		case <-deadline.C:
			_ = srv.Shutdown()
			err := errors.New("代理实例启动超时")
			m.recordError(id, err)
			return err
		case <-ticker.C:
			if !srv.IsRunning() {
				continue
			}

			m.mu.Lock()
			rt := m.instances[id]
			if rt == nil {
				rt = &instanceRuntime{}
				m.instances[id] = rt
			}
			rt.cfg = cfg
			rt.srv = srv
			rt.startedAt = time.Now()
			rt.lastError = ""
			m.mu.Unlock()

			go m.watchServerExit(id, srv, errCh)
			return nil
		}
	}
}

func (m *Manager) watchServerExit(id string, srv *Server, errCh <-chan error) {
	err := <-errCh
	m.mu.Lock()
	defer m.mu.Unlock()
	rt := m.instances[id]
	if rt == nil || rt.srv != srv {
		return
	}
	rt.srv = nil
	rt.lastExitAt = time.Now()
	if err == nil {
		rt.lastExitOK = true
		rt.lastError = ""
	} else {
		rt.lastExitOK = false
		rt.lastError = err.Error()
	}
	delete(m.lastTraffic, id)
}

func (m *Manager) recordError(id string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt := m.instances[id]
	if rt == nil {
		rt = &instanceRuntime{}
		m.instances[id] = rt
	}
	rt.lastExitAt = time.Now()
	rt.lastExitOK = false
	if err != nil {
		rt.lastError = err.Error()
	} else {
		rt.lastError = "未知错误"
	}
}

func (m *Manager) Stop(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	rt := m.instances[id]
	if rt == nil || rt.srv == nil {
		m.mu.Unlock()
		return nil
	}
	srv := rt.srv
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		done <- srv.Shutdown()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Restart(ctx context.Context, id string) error {
	if err := m.Stop(ctx, id); err != nil {
		return err
	}
	return m.Start(ctx, id)
}

func (m *Manager) GetStatus(id string) InstanceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	cfg, ok := m.configByID[id]
	if !ok {
		return InstanceStatus{ID: id, Running: false, LastError: "实例不存在"}
	}
	rt := m.instances[id]
	st := InstanceStatus{
		ID:          id,
		Mode:        cfg.Mode,
		ListenAddr:  cfg.ListenAddr,
		ListenPort:  cfg.ListenPort,
		Interface:   cfg.Interface,
		AuthEnabled: cfg.AuthEnabled,
	}
	if rt == nil {
		return st
	}
	if rt.srv == nil {
		st.StartedAt = rt.startedAt
		st.LastExitAt = rt.lastExitAt
		st.LastExitOK = rt.lastExitOK
		st.LastError = rt.lastError
		return st
	}

	st.Running = true
	st.StartedAt = rt.startedAt
	st.LastExitAt = rt.lastExitAt
	st.LastExitOK = rt.lastExitOK
	st.LastError = rt.lastError
	return st
}

func (m *Manager) ListStatus() []InstanceStatus {
	m.mu.Lock()
	ids := make([]string, 0, len(m.configByID))
	for id := range m.configByID {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	sort.Strings(ids)

	out := make([]InstanceStatus, 0, len(ids))
	for _, id := range ids {
		out = append(out, m.GetStatus(id))
	}
	return out
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	ids := make([]string, 0, len(m.instances))
	for id := range m.instances {
		ids = append(ids, id)
	}
	m.mu.Unlock()

	for _, id := range ids {
		if err := m.Stop(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) IsRunning(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt := m.instances[id]
	return rt != nil && rt.srv != nil && rt.srv.IsRunning()
}

// SnapshotAndResetTraffic 获取各实例流量增量。
func (m *Manager) SnapshotAndResetTraffic() map[string]TrafficCounters {
	m.mu.Lock()
	running := make(map[string]*Server, len(m.instances))
	for id, rt := range m.instances {
		if rt != nil && rt.srv != nil {
			running[id] = rt.srv
		}
	}
	m.mu.Unlock()

	out := make(map[string]TrafficCounters, len(running))
	for id, srv := range running {
		stats := srv.GetStats()
		if stats == nil {
			continue
		}
		rx := stats["bytes_received"]
		tx := stats["bytes_sent"]

		m.mu.Lock()
		last := m.lastTraffic[id]
		m.lastTraffic[id] = [2]int64{rx, tx}
		m.mu.Unlock()

		drx := rx - last[0]
		dtx := tx - last[1]
		if drx < 0 {
			drx = 0
		}
		if dtx < 0 {
			dtx = 0
		}
		if drx == 0 && dtx == 0 {
			continue
		}
		out[id] = TrafficCounters{Uplink: dtx, Downlink: drx}
	}
	return out
}

func instanceConfigEqual(a, b InstanceConfig) bool {
	return a.ID == b.ID &&
		a.Mode == b.Mode &&
		a.Enabled == b.Enabled &&
		a.ListenAddr == b.ListenAddr &&
		a.ListenPort == b.ListenPort &&
		a.Interface == b.Interface &&
		a.AuthEnabled == b.AuthEnabled &&
		a.Username == b.Username &&
		a.Password == b.Password
}
