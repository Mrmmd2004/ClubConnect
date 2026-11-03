package backends

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
	"clubconnect/internal/proc"
	"clubconnect/internal/socks"
)

var clog = logx.For("chain")

// Chain is "WARP -> Psiphon" / "WARP -> Tor": the in-process WARP tunnel is exposed
// to the second engine as a private SOCKS5 port (the gate), and that engine is told to use it
// as its upstream proxy. Everything the engine sends - its handshake with Psiphon servers or
// Tor relays, and so your traffic inside - therefore leaves through Cloudflare first.
type Chain struct {
	core.Base // its error is a start error of the inner engine
	name      string
	w         core.Backend // any WARP variant (built-in WireGuard, aether-based, or auto)
	inner     core.Backend
	setUp     func(hostport string)
	gatePort  atomic.Int32
}

func NewChainPsiphon(cfg *config.Config, variant string) *Chain {
	p := NewPsiphon(cfg)
	return &Chain{name: "warp+psiphon", w: NewWarpBackend(cfg, variant), inner: p,
		setUp: func(hp string) { p.Upstream = "socks5://" + hp }}
}

func NewChainTor(cfg *config.Config, variant string) *Chain {
	t := NewTor(cfg)
	return &Chain{name: "warp+tor", w: NewWarpBackend(cfg, variant), inner: t,
		setUp: func(hp string) { t.Upstream = hp }}
}

func (c *Chain) Name() string      { return c.name }
func (c *Chain) Variant() string   { return core.VariantOf(c.w) }
func (c *Chain) SupportsUDP() bool { return false }
func (c *Chain) Ready() bool       { return c.inner.Ready() }

func (c *Chain) LastError() string {
	if s := c.Base.LastError(); s != "" {
		return s
	}
	if !c.w.Ready() {
		if e := c.w.LastError(); e != "" {
			return "warp: " + e
		}
		return "waiting for WARP (" + orDefault(core.VariantOf(c.w), "starting") + ")"
	}
	return c.inner.LastError()
}

func (c *Chain) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.inner.DialTCP(ctx, addr)
}

func (c *Chain) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, core.NoUDP(c.name + " has no UDP")
}

func (c *Chain) Start(parent context.Context) error {
	port := proc.FreePort()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		proc.ReleasePort(port)
		return err
	}
	c.gatePort.Store(int32(port))
	ctx := c.Begin(parent)
	c.SetError("")
	c.setUp(ln.Addr().String())
	if err := c.w.Start(ctx); err != nil {
		c.End(0)
		ln.Close()
		proc.ReleasePort(int(c.gatePort.Swap(0)))
		return err
	}
	c.Go(func() { socks.ServeGate(ctx, ln, c.w.DialTCP) })
	c.Go(func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for !c.w.Ready() {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
		clog.Infof("WARP is up (%s), starting %s through it", orDefault(core.VariantOf(c.w), "?"), c.inner.Name())
		if err := c.inner.Start(ctx); err != nil {
			logx.For(c.inner.Name()).Infof("%v", err)
			c.SetError(err.Error())
		}
	})
	return nil
}

func (c *Chain) Stop() {
	c.End(0)
	c.inner.Stop()
	c.w.Stop()
	if p := int(c.gatePort.Swap(0)); p != 0 {
		proc.ReleasePort(p)
	}
}
