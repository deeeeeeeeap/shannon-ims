package swu

import (
	"context"
	"errors"
	"sync"

	"github.com/1239t/swu-go/pkg/logger"
	"go.uber.org/zap"
)

type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	cancels  map[string]context.CancelFunc
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		cancels:  make(map[string]context.CancelFunc),
	}
}

func (m *SessionManager) Start(ctx context.Context, id string, cfg *Config) (*Session, error) {
	if id == "" {
		return nil, errors.New("session id 不能为空")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[id]; ok {
		return nil, errors.New("session id 已存在")
	}

	// 创建带设备 ID 的 logger
	devLogger := logger.With(zap.String("device", id))
	s := NewSession(cfg, devLogger)
	sessCtx, cancel := context.WithCancel(ctx)
	m.sessions[id] = s
	m.cancels[id] = cancel

	go func() {
		if err := s.Connect(sessCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("ePDG 会话退出", logger.Err(err))
		}
	}()

	return s, nil
}

func (m *SessionManager) Stop(id string) error {
	m.mu.Lock()
	cancel, ok := m.cancels[id]
	if ok {
		delete(m.cancels, id)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("session id 不存在")
	}
	cancel()
	return nil
}

func (m *SessionManager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}
