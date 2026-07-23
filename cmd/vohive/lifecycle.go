package main

import (
	"context"
	"errors"
	"sync"
)

var errApplicationLifecycleStopping = errors.New("application lifecycle is stopping")

type applicationLifecycle struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu               sync.Mutex
	accepting        bool
	cleanupAccepting bool
	active           int
	idle             chan struct{}
}

func newApplicationLifecycle(parent context.Context) *applicationLifecycle {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	idle := make(chan struct{})
	close(idle)
	return &applicationLifecycle{
		ctx:              ctx,
		cancel:           cancel,
		accepting:        true,
		cleanupAccepting: true,
		idle:             idle,
	}
}

func (l *applicationLifecycle) RunCleanup(ctx context.Context, run func()) error {
	if l == nil || run == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan struct{})
	l.mu.Lock()
	if !l.cleanupAccepting {
		l.mu.Unlock()
		return errApplicationLifecycleStopping
	}
	if l.active == 0 {
		l.idle = make(chan struct{})
	}
	l.active++
	l.mu.Unlock()

	go func() {
		defer close(done)
		defer l.taskDone()
		run()
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *applicationLifecycle) Go(run func(context.Context)) bool {
	if l == nil || run == nil {
		return false
	}
	l.mu.Lock()
	if !l.accepting || l.ctx.Err() != nil {
		l.mu.Unlock()
		return false
	}
	if l.active == 0 {
		l.idle = make(chan struct{})
	}
	l.active++
	l.mu.Unlock()

	go func() {
		defer l.taskDone()
		run(l.ctx)
	}()
	return true
}

func (l *applicationLifecycle) Context() context.Context {
	if l == nil || l.ctx == nil {
		return context.Background()
	}
	return l.ctx
}

func (l *applicationLifecycle) Cancel() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.accepting = false
	l.mu.Unlock()
	l.cancel()
}

func (l *applicationLifecycle) taskDone() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active <= 0 {
		return
	}
	l.active--
	if l.active == 0 {
		close(l.idle)
	}
}

func (l *applicationLifecycle) Stop(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.Cancel()
	l.mu.Lock()
	l.cleanupAccepting = false
	idle := l.idle
	l.mu.Unlock()

	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
