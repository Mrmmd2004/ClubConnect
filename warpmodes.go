package main

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WARP is not one thing. Aether can reach Cloudflare in several ways, and a network that blocks
// one of them usually lets another through. Club Connect offers all of them as "variants" of the
// WARP engine; every mode that contains WARP (warp, warp+psiphon, warp+tor, and the WARP part of
// auto) can use any variant, chosen per mode.
var warpVariants = []string{"auto", "wg", "masque", "masque-h2", "gool", "gool-classic", "mim", "wg-noize"}

var variantLabels = map[string]string{
	"auto":         "Auto            tries them in waves, keeps the first that really carries traffic",
	"wg":           "WireGuard       built in, nothing else needed (UDP 2408 and fallbacks)",
	"masque":       "MASQUE HTTP/3   Cloudflare's main protocol, looks like HTTPS (UDP 443)  [aether]",
	"masque-h2":    "MASQUE HTTP/2   same tunnel over TCP 443, survives QUIC blocking  [aether]",
	"gool":         "Gool            WireGuard inside MASQUE, a different exit address  [aether]",
	"gool-classic": "WARP-in-WARP     WireGuard inside WireGuard  [aether]",
	"mim":          "MASQUE-in-MASQUE two MASQUE hops, a different exit address  [aether]",
	"wg-noize":     "WireGuard+noize WireGuard with a disguised handshake, for strict networks  [aether]",
}

// Waves for variant "auto": everything in one wave is started together and the first that
// passes a real data check wins. Later waves are only tried if the earlier ones got nowhere.
var defaultAutoWaves = []string{"wg+masque", "masque-h2+gool", "wg-noize+mim", "gool-classic"}

const autoWaveTimeout = 55 * time.Second

var variantShort = map[string]string{
	"auto":         "Auto",
	"wg":           "WireGuard",
	"masque":       "MASQUE HTTP/3",
	"masque-h2":    "MASQUE HTTP/2",
	"gool":         "Gool (WireGuard in MASQUE)",
	"gool-classic": "WARP-in-WARP",
	"mim":          "MASQUE-in-MASQUE",
	"wg-noize":     "WireGuard + noize",
}

// variantName is the short human name of a variant ("auto: wg" style values pass through).
func variantName(v string) string {
	if n, ok := variantShort[v]; ok {
		return n
	}
	return v
}

// normVariant accepts the canonical names and a few spellings; "" means unknown or empty.
func normVariant(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", "-", " ", "-", "+", "-").Replace(s)
	switch s {
	case "wireguard", "warp", "classic", "wireguard-only":
		return "wg"
	case "h3", "quic", "masque-h3", "masque-quic", "http3":
		return "masque"
	case "h2", "http2", "masque-http2":
		return "masque-h2"
	case "warp-in-warp", "wiw-classic":
		return "gool-classic"
	case "masque-in-masque":
		return "mim"
	case "noize", "wg-obfs", "wireguard-noize":
		return "wg-noize"
	}
	for _, v := range warpVariants {
		if s == v {
			return v
		}
	}
	return ""
}

func variantNeedsAether(v string) bool { return v != "wg" && v != "auto" && v != "" }

func variantAvailable(cfg *Config, v string) bool {
	return !variantNeedsAether(v) || aetherBin(cfg) != ""
}

// newWarpBackend builds the WARP engine for a variant.
func newWarpBackend(cfg *Config, variant string) Backend {
	switch variant {
	case "wg":
		return NewWarp(cfg)
	case "auto", "":
		return NewAutoWarp(cfg)
	}
	return NewAetherWarp(cfg, variant)
}

// variantOf reports the variant a backend is using right now ("" if it does not say).
func variantOf(b Backend) string {
	if vb, ok := b.(interface{ Variant() string }); ok {
		return vb.Variant()
	}
	return ""
}

// ---------- AutoWarp ----------

// AutoWarp is the "auto" variant: it finds a WARP route that works on this network and keeps it,
// and when that route dies it searches again from the top.
type AutoWarp struct {
	cfg *Config
	err atomic.Value // string

	mu     sync.Mutex
	cur    Backend
	curVar string
	cancel context.CancelFunc
}

func NewAutoWarp(cfg *Config) *AutoWarp { return &AutoWarp{cfg: cfg} }

func (a *AutoWarp) Name() string { return "warp" }

func (a *AutoWarp) get() (Backend, string) {
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

func (a *AutoWarp) LastError() string { s, _ := a.err.Load().(string); return s }

func (a *AutoWarp) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	b, _ := a.get()
	if b == nil {
		return nil, errors.New("warp (auto) is still looking for a route that works")
	}
	return b.DialTCP(ctx, addr)
}

func (a *AutoWarp) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	b, _ := a.get()
	if b == nil {
		return nil, errors.New("warp (auto) is still looking for a route that works")
	}
	return b.DialUDP(ctx, addr)
}

func (a *AutoWarp) Start(ctx context.Context) error {
	cctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()
	go a.run(cctx)
	return nil
}

func (a *AutoWarp) Stop() {
	a.mu.Lock()
	cancel, b := a.cancel, a.cur
	a.cancel, a.cur, a.curVar = nil, nil, ""
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if b != nil {
		b.Stop()
	}
}

// waves returns the variants worth trying here, grouped; variants that need aether are left out
// when aether is missing.
func (a *AutoWarp) waves() [][]string {
	spec := a.cfg.Warp.Auto
	if len(spec) == 0 {
		spec = defaultAutoWaves
	}
	var out [][]string
	for _, w := range spec {
		var wave []string
		for _, p := range strings.Split(w, "+") {
			v := normVariant(p)
			if v == "" || v == "auto" || !variantAvailable(a.cfg, v) {
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
	b      Backend
	v      string
	cancel context.CancelFunc
}

func (a *AutoWarp) run(ctx context.Context) {
	if aetherBin(a.cfg) == "" {
		log.Printf("[warp] auto: aether%s was not found, so only the built-in WireGuard can be tried (put aether%s next to clubconnect to add MASQUE, gool, mim and noize)", exeSuffix(), exeSuffix())
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
			a.err.Store("")
			log.Printf("[warp] auto: using %s", variantName(pick.v))
			a.hold(ctx, pick.b)
			a.mu.Lock()
			a.cur, a.curVar = nil, ""
			a.mu.Unlock()
			pick.b.Stop()
			pick.cancel()
			if ctx.Err() == nil {
				log.Printf("[warp] auto: %s stopped working, searching again", variantName(pick.v))
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
				a.err.Store("no WARP route worked yet")
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
		b := newWarpBackend(a.cfg, v)
		cctx, cancel := context.WithCancel(ctx)
		if err := b.Start(cctx); err != nil {
			cancel()
			log.Printf("[warp] auto: %s cannot start: %v", v, err)
			continue
		}
		cs = append(cs, &autoPick{b: b, v: v, cancel: cancel})
	}
	if len(cs) == 0 {
		return nil
	}
	log.Printf("[warp] auto: trying %s", strings.Join(wave, " + "))
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
		a.err.Store(msg)
		log.Printf("[warp] auto: %s", msg)
	}
	return win
}

// hold returns when b has been not-ready for 20 seconds in a row, or when ctx ends.
func (a *AutoWarp) hold(ctx context.Context, b Backend) {
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
