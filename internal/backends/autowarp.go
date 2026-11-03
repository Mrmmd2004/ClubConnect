package backends

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
	"clubconnect/internal/proc"
)

// DefaultAutoWaves are the waves of variant "auto": everything in one wave is started together
// and the first that passes a real data check wins. Later waves are only tried if the earlier
// ones got nowhere. MASQUE over HTTP/2 goes first and alone: it is the route that has worked
// best, so it is not allowed to lose a race against the faster-to-start WireGuard.
var DefaultAutoWaves = []string{"masque-h2", "wg+masque", "gool+wg-noize", "mim", "gool-classic"}

const autoWaveTimeout = 55 * time.Second

// AutoWarp is the "auto" variant: it finds a WARP route that works on this network and keeps it,
// and when that route dies it searches again from the top.
type AutoWarp struct {
	core.Base
	cfg *config.Config
	log logx.Logger

	mu     sync.Mutex
	cur    core.Backend
	curVar string
}

func NewAutoWarp(cfg *config.Config) *AutoWarp { return &AutoWarp{cfg: cfg, log: logx.For("warp")} }

func (a *AutoWarp) Name() string { return "warp" }

func (a *AutoWarp) get() (core.Backend, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cur, a.curVar
}

func (a *AutoWarp) Variant() string {
	if _, v := a.get(); v != "" {
		return "auto: " + v
	}
	return "auto (searching)"
}

func (a *AutoWarp) Ready() bool {
	b, _ := a.get()
	return b != nil && b.Ready()
}

func (a *AutoWarp) SupportsUDP() bool {
	b, _ := a.get()
	return b != nil && b.SupportsUDP()
}

func (a *AutoWarp) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	b, _ := a.get()
	if b == nil {
		return nil, core.NotReady("warp (auto) is still looking for a route that works")
	}
	return b.DialTCP(ctx, addr)
}

func (a *AutoWarp) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	b, _ := a.get()
	if b == nil {
		return nil, core.NotReady("warp (auto) is still looking for a route that works")
	}
	return b.DialUDP(ctx, addr)
}

func (a *AutoWarp) Start(ctx context.Context) error {
	cctx := a.Begin(ctx)
	a.Go(func() { a.run(cctx) })
	return nil
}

func (a *AutoWarp) Stop() {
	a.End(0)
	a.mu.Lock()
	b := a.cur
	a.cur, a.curVar = nil, ""
	a.mu.Unlock()
	if b != nil {
		b.Stop()
	}
}

// waves returns the variants worth trying here, grouped; variants that need aether are left out
// when aether is missing.
func (a *AutoWarp) waves() [][]string {
	spec := a.cfg.Warp.Auto
	if len(spec) == 0 {
		spec = DefaultAutoWaves
	}
	var out [][]string
	for _, w := range spec {
		var wave []string
		for _, p := range strings.Split(w, "+") {
			v := config.NormVariant(p)
			if v == "" || v == "auto" || !VariantAvailable(a.cfg, v) {
				continue
			}
			wave = append(wave, v)
		}
		if len(wave) > 0 {
			out = append(out, wave)
		}
	}
	return out
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

type autoPick struct {
	b      core.Backend
	v      string
	cancel context.CancelFunc
}

func (a *AutoWarp) run(ctx context.Context) {
	if AetherBin(a.cfg) == "" {
		a.log.Infof("auto: aether%s was not found, so only the built-in WireGuard can be tried (it is normally built into clubconnect; or put aether%s next to it to add MASQUE, gool, mim and noize)", proc.ExeSuffix(), proc.ExeSuffix())
	}
	for ctx.Err() == nil {
		got := false
		for _, wave := range a.waves() {
			if ctx.Err() != nil {
				return
			}
			pick := a.tryWave(ctx, wave)
			if pick == nil {
				continue
			}
			got = true
			a.mu.Lock()
			a.cur, a.curVar = pick.b, pick.v
			a.mu.Unlock()
			a.SetError("")
			a.log.Infof("auto: using %s", config.VariantName(pick.v))
			a.hold(ctx, pick.b)
			a.mu.Lock()
			a.cur, a.curVar = nil, ""
			a.mu.Unlock()
			pick.b.Stop()
			pick.cancel()
			if ctx.Err() == nil {
				a.log.Infof("auto: %s stopped working, searching again", config.VariantName(pick.v))
			}
			break
		}
		if ctx.Err() != nil {
			return
		}
		if got {
			sleepCtx(ctx, 2*time.Second)
		} else {
			if a.LastError() == "" {
				a.SetError("no WARP route worked yet")
			}
			sleepCtx(ctx, 8*time.Second)
		}
	}
}

// tryWave starts every variant of the wave, waits for the first one that is Ready and stops the
// others. The winner keeps running; its cancel function is returned with it.
func (a *AutoWarp) tryWave(ctx context.Context, wave []string) *autoPick {
	var cs []*autoPick
	for _, v := range wave {
		b := NewWarpBackend(a.cfg, v)
		cctx, cancel := context.WithCancel(ctx)
		if err := b.Start(cctx); err != nil {
			cancel()
			a.log.Infof("auto: %s cannot start: %v", v, err)
			continue
		}
		cs = append(cs, &autoPick{b: b, v: v, cancel: cancel})
	}
	if len(cs) == 0 {
		return nil
	}
	a.log.Infof("auto: trying %s", strings.Join(wave, " + "))
	deadline := time.NewTimer(autoWaveTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	var win *autoPick
wait:
	for {
		select {
		case <-ctx.Done():
			break wait
		case <-deadline.C:
			break wait
		case <-tick.C:
			for _, c := range cs {
				if c.b.Ready() {
					win = c
					break wait
				}
			}
		}
	}
	var why []string
	for _, c := range cs {
		if c == win {
			continue
		}
		if e := c.b.LastError(); e != "" {
			why = append(why, c.v+": "+e)
		}
		c.b.Stop()
		c.cancel()
	}
	if win == nil && ctx.Err() == nil {
		msg := "no answer from " + strings.Join(wave, " + ") + " within " + autoWaveTimeout.String()
		if len(why) > 0 {
			msg += " (" + strings.Join(why, "; ") + ")"
		}
		a.SetError(msg)
		a.log.Infof("auto: %s", msg)
	}
	return win
}

// hold returns when b has been not-ready for 20 seconds in a row, or when ctx ends.
func (a *AutoWarp) hold(ctx context.Context, b core.Backend) {
	var down time.Time
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if b.Ready() {
			down = time.Time{}
			continue
		}
		if down.IsZero() {
			down = time.Now()
		}
		if time.Since(down) > 20*time.Second {
			return
		}
	}
}
