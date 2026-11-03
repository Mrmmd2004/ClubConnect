// Package core is the heart of Club Connect: the Backend contract every engine fulfils, the
// small base struct that removes the repeated ready/error/cancel code, and the Manager that
// health-checks the engines, picks the best one and fails over between them.
package core

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Backend is one way out to the internet (WARP, Psiphon, Tor, or a chain of two of them).
type Backend interface {
	Name() string
	Start(ctx context.Context) error // must not block: supervision runs in goroutines
	Ready() bool
	LastError() string
	SupportsUDP() bool
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
	Stop()
}

// Varianter is implemented by backends that run in a variant (the WARP engines: "wg",
// "masque", "auto: gool", ...). It is optional.
type Varianter interface{ Variant() string }

// HealthChecker is implemented by a backend that knows a better health test than the Manager's
// default (an HTTP request through DialTCP). It is optional.
type HealthChecker interface {
	Health(ctx context.Context) (latency time.Duration, ok bool)
}

// VariantOf reports the variant a backend is using right now ("" if it does not say).
func VariantOf(b Backend) string {
	if v, ok := b.(Varianter); ok {
		return v.Variant()
	}
	return ""
}

// Base holds what every backend repeated: the ready flag, the last error and the cancel /
// wait-for-goroutines logic of Start and Stop. Embed it and override only what differs
// (the WARP backends, for instance, override Ready).
//
//	func (b *X) Start(parent context.Context) error {
//	    ctx := b.Begin(parent)
//	    b.Spawn(func() { b.run(ctx) })
//	    return nil
//	}
//	func (b *X) Stop() { b.End(5 * time.Second) }
type Base struct {
	ready atomic.Bool
	err   atomic.Value // string

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (b *Base) Ready() bool     { return b.ready.Load() }
func (b *Base) SetReady(v bool) { b.ready.Store(v) }

// LastError is the last problem reported with SetError ("" when there is none).
func (b *Base) LastError() string { s, _ := b.err.Load().(string); return s }

// SetError records a problem for LastError; the empty string clears it.
func (b *Base) SetError(msg string) { b.err.Store(msg) }

// Begin starts a run: it returns the context the backend's goroutines must use. A run that is
// still active is cancelled first.
func (b *Base) Begin(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	b.mu.Lock()
	old := b.cancel
	b.cancel = cancel
	b.mu.Unlock()
	if old != nil {
		old()
	}
	return ctx
}

// Spawn runs fn in a goroutine that End waits for.
func (b *Base) Spawn(fn func()) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		fn()
	}()
}

// Go runs fn in a goroutine that End does not wait for.
func (b *Base) Go(fn func()) { go fn() }

// End stops the run: ready becomes false, the context is cancelled and, when wait > 0, End waits
// for the Spawn goroutines but not longer than wait. It is safe to call twice.
func (b *Base) End(wait time.Duration) {
	b.mu.Lock()
	cancel := b.cancel
	b.cancel = nil
	b.mu.Unlock()
	b.ready.Store(false)
	if cancel != nil {
		cancel()
	}
	if wait <= 0 {
		return
	}
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(wait):
	}
}
