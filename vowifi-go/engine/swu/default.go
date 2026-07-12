package swu

import (
	"context"
	"sync"
)

var (
	defaultManagerOnce sync.Once
	defaultManagerInst *Manager
	defaultManagerErr  error
	defaultManagerMu   sync.RWMutex
	defaultManagerOpts *ManagerOptions
)

// SetDefaultManagerOptions overrides the options used by the package-level
// Dial() convenience path. It must be called before the first Dial().
func SetDefaultManagerOptions(opts ManagerOptions) {
	defaultManagerMu.Lock()
	defer defaultManagerMu.Unlock()
	cloned := opts
	defaultManagerOpts = &cloned
}

func currentDefaultManagerOptions() ManagerOptions {
	defaultManagerMu.RLock()
	defer defaultManagerMu.RUnlock()
	if defaultManagerOpts != nil {
		return *defaultManagerOpts
	}
	return DefaultManagerOptions()
}

// defaultManager lazily constructs and starts the package-level Manager
// package-level Dial() uses, exactly once. A failed Start is cached and
// returned on every subsequent call rather than retried automatically: a
// silently-retrying background init could mask a persistent misconfiguration
// (missing charon binary, AppArmor blocking something new) behind seemingly
// one-off Dial failures.
func defaultManager(ctx context.Context) (*Manager, error) {
	defaultManagerOnce.Do(func() {
		defaultManagerInst, defaultManagerErr = NewManager(currentDefaultManagerOptions())
		if defaultManagerErr != nil {
			return
		}
		defaultManagerErr = defaultManagerInst.Start(ctx)
	})
	return defaultManagerInst, defaultManagerErr
}
