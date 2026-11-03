package backends

import (
	"context"
	"net"
	"sync/atomic"

	"clubconnect/internal/core"
	"clubconnect/internal/proc"
)

func procExit() proc.ExitInfo { return proc.ExitInfo{Started: true, ExitCode: 1} }

// PluggableTransportsInstalled tells whether lyrebird or snowflake exist on this machine (the
// tor bridge test needs them to be absent).
func PluggableTransportsInstalled(c interface{}) bool {
	return proc.FindBinary("", "lyrebird", "obfs4proxy", "snowflake-client") != ""
}

type stubWarp struct {
	core.Base
	ready   atomic.Bool
	stopped atomic.Bool
}

func (s *stubWarp) Name() string                { return "warp" }
func (s *stubWarp) Start(context.Context) error { return nil }
func (s *stubWarp) Ready() bool                 { return s.ready.Load() }
func (s *stubWarp) SupportsUDP() bool           { return true }
func (s *stubWarp) Stop()                       { s.stopped.Store(true); s.ready.Store(false) }
func (s *stubWarp) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, core.ErrNotReady
}
func (s *stubWarp) DialUDP(context.Context, string) (net.Conn, error) {
	return nil, core.ErrNotReady
}

type stubInner struct {
	core.Base
	started  atomic.Bool
	stopped  atomic.Bool
	startErr error
}

func (s *stubInner) Name() string { return "tor" }
func (s *stubInner) Start(context.Context) error {
	s.started.Store(true)
	return s.startErr
}
func (s *stubInner) SupportsUDP() bool { return false }
func (s *stubInner) Stop()             { s.stopped.Store(true) }
func (s *stubInner) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, core.ErrNotReady
}
func (s *stubInner) DialUDP(context.Context, string) (net.Conn, error) {
	return nil, core.ErrNotReady
}
