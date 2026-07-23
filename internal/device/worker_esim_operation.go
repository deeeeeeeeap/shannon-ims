package device

import (
	"context"
	"sync"

	"github.com/1239t/vohive/internal/db"
	"github.com/1239t/vohive/internal/esim"
)

// workerESIMOperationOwner owns the physical eSIM switch work for one Worker
// generation. Its zero value accepts leases and can be stopped exactly once.
type workerESIMOperationOwner struct {
	mu          sync.Mutex
	initialized bool
	accepting   bool
	ctx         context.Context
	cancel      context.CancelFunc
	active      int
	idle        chan struct{}
}

type workerESIMOperationLease struct {
	owner      *workerESIMOperationOwner
	worker     *Worker
	generation uint64
	ctx        context.Context
	release    sync.Once
	released   bool
}

func (o *workerESIMOperationOwner) acquire(parent context.Context, worker *Worker) (*workerESIMOperationLease, bool) {
	if o == nil || worker == nil || worker.generation == 0 {
		return nil, false
	}
	if parent == nil {
		parent = context.Background()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.initializeLocked(parent)
	if !o.accepting || o.ctx.Err() != nil {
		return nil, false
	}
	if o.active == 0 {
		o.idle = make(chan struct{})
	}
	o.active++
	return &workerESIMOperationLease{
		owner:      o,
		worker:     worker,
		generation: worker.generation,
		ctx:        o.ctx,
	}, true
}

func (o *workerESIMOperationOwner) stop(parent context.Context) <-chan struct{} {
	if o == nil {
		return closedESIMOperationSignal()
	}
	if parent == nil {
		parent = context.Background()
	}
	o.mu.Lock()
	o.initializeLocked(parent)
	if o.accepting {
		o.accepting = false
		o.cancel()
	}
	idle := o.idle
	o.mu.Unlock()
	return idle
}

func (o *workerESIMOperationOwner) initializeLocked(parent context.Context) {
	if o.initialized {
		return
	}
	o.ctx, o.cancel = context.WithCancel(parent)
	o.accepting = true
	o.idle = closedESIMOperationSignal()
	o.initialized = true
}

func (l *workerESIMOperationLease) Context() context.Context {
	if l == nil || l.ctx == nil {
		return context.Background()
	}
	return l.ctx
}

func (l *workerESIMOperationLease) validFor(worker *Worker) bool {
	if l == nil || worker == nil || l.worker != worker || l.generation == 0 ||
		worker.generation != l.generation || l.Context().Err() != nil {
		return false
	}
	if worker.stop != nil {
		select {
		case <-worker.stop:
			return false
		default:
		}
	}
	return true
}

func (l *workerESIMOperationLease) RunPhysical(apply func() error) error {
	if l == nil || l.owner == nil || l.worker == nil || apply == nil {
		return db.ErrESIMSwitchOperationStale
	}
	l.owner.mu.Lock()
	if l.released || !l.owner.initialized || !l.owner.accepting ||
		l.owner.ctx == nil || l.owner.ctx.Err() != nil || l.owner.active <= 0 ||
		l.generation == 0 || l.worker.generation != l.generation {
		l.owner.mu.Unlock()
		return db.ErrESIMSwitchOperationStale
	}
	if l.worker.stop != nil {
		select {
		case <-l.worker.stop:
			l.owner.mu.Unlock()
			return db.ErrESIMSwitchOperationStale
		default:
		}
	}
	l.owner.mu.Unlock()
	return apply()
}

func (l *workerESIMOperationLease) Release() {
	if l == nil || l.owner == nil {
		return
	}
	l.release.Do(func() {
		l.owner.mu.Lock()
		defer l.owner.mu.Unlock()
		l.released = true
		if l.owner.active <= 0 {
			return
		}
		l.owner.active--
		if l.owner.active == 0 {
			close(l.owner.idle)
		}
	})
}

func closedESIMOperationSignal() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (w *Worker) acquireESIMOperationLease(parent context.Context) (*workerESIMOperationLease, bool) {
	if w == nil {
		return nil, false
	}
	if w.stop != nil {
		select {
		case <-w.stop:
			return nil, false
		default:
		}
	}
	return w.esimOperationOwner.acquire(parent, w)
}

func (w *Worker) stopESIMOperationLeases(parent context.Context) <-chan struct{} {
	if w == nil {
		return closedESIMOperationSignal()
	}
	return w.esimOperationOwner.stop(parent)
}

func (w *Worker) acquireESIMManagerSwitchLease(requestCtx context.Context) (esim.SwitchOperationLease, error) {
	if requestCtx != nil {
		if err := requestCtx.Err(); err != nil {
			return nil, err
		}
	}
	parent := context.Background()
	if w != nil && w.Pool != nil && w.Pool.ctx != nil {
		parent = w.Pool.ctx
	}
	lease, ok := w.acquireESIMOperationLease(parent)
	if !ok {
		return nil, db.ErrESIMSwitchOperationStale
	}
	return lease, nil
}
