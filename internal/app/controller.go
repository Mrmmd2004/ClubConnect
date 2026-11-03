// Package app ties the pieces together: the Controller that starts and stops the modes, and the
// interactive menu.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"clubconnect/internal/api"
	"clubconnect/internal/backends"
	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/inbound"
	"clubconnect/internal/logx"
	"clubconnect/internal/proc"
)

// Errors of the Controller (their texts are what the menu and the API show).
var (
	ErrNotRunning     = errors.New("not running - start a mode first")
	ErrUnknownMode    = errors.New("unknown mode")
	ErrUnknownVariant = errors.New("unknown WARP variant")
	ErrMissingProgram = errors.New("a helper program is missing")
	ErrNoBackends     = errors.New("no backends enabled")
	ErrPortInUse      = errors.New("cannot listen on the proxy port")
)

// Info names the program (set by main).
type Info struct{ Name, Version string }

var log = logx.For("core")

// Controller starts and stops the engines on demand and owns the proxy listener.
type Controller struct {
	cfg    *config.Config
	info   Info
	appCtx context.Context

	mu      sync.Mutex
	mgr     *core.Manager
	mode    string
	variant string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewController(ctx context.Context, cfg *config.Config, info Info) *Controller {
	return &Controller{cfg: cfg, appCtx: ctx, info: info}
}

// BackendsFor builds the engines of a mode. The second result is the backend name the manager is
// pinned to ("" for auto mode, which lets it pick).
func BackendsFor(cfg *config.Config, mode, variant string) ([]core.Backend, string, error) {
	switch mode {
	case "auto":
		var bs []core.Backend
		for _, n := range cfg.Order {
			switch strings.TrimSpace(n) {
			case "warp":
				bs = append(bs, backends.NewWarpBackend(cfg, variant))
			case "psiphon":
				bs = append(bs, backends.NewPsiphon(cfg))
			case "tor":
				bs = append(bs, backends.NewTor(cfg))
			default:
				return nil, "", fmt.Errorf("unknown backend %q in order", n)
			}
		}
		if len(bs) == 0 {
			return nil, "", ErrNoBackends
		}
		return bs, "", nil
	case "warp":
		return []core.Backend{backends.NewWarpBackend(cfg, variant)}, "warp", nil
	case "psiphon":
		return []core.Backend{backends.NewPsiphon(cfg)}, "psiphon", nil
	case "tor":
		return []core.Backend{backends.NewTor(cfg)}, "tor", nil
	case "warp+psiphon":
		return []core.Backend{backends.NewChainPsiphon(cfg, variant)}, "warp+psiphon", nil
	case "warp+tor":
		return []core.Backend{backends.NewChainTor(cfg, variant)}, "warp+tor", nil
	}
	return nil, "", core.Wrap(ErrUnknownMode, fmt.Sprintf("unknown mode %q", mode))
}

// Preflight refuses a manual mode whose program is missing, so the failure is shown at once.
func Preflight(cfg *config.Config, mode, variant string) error {
	if config.ModeUsesWarp(mode) && config.VariantNeedsAether(variant) && backends.AetherBin(cfg) == "" {
		return core.Wrap(ErrMissingProgram, fmt.Sprintf("WARP variant %q needs aether%s (release builds carry it inside clubconnect; otherwise put it next to clubconnect or set its path in Settings); choose the built-in \"wg\" or \"auto\" instead", variant, proc.ExeSuffix()))
	}
	if (mode == "psiphon" || mode == "warp+psiphon") && backends.PsiphonBin(cfg) == "" {
		return core.Wrap(ErrMissingProgram, "psiphon-tunnel-core was not found (release builds carry it inside clubconnect; otherwise put it next to clubconnect or set its path in Settings)")
	}
	if (mode == "tor" || mode == "warp+tor") && backends.TorBin(cfg) == "" {
		return core.Wrap(ErrMissingProgram, "tor was not found: put tor.exe next to clubconnect, install Tor Browser, or set its path in Settings")
	}
	return nil
}

// Start stops whatever runs and starts the given mode.
// The mode may carry a WARP variant: "warp@masque", "warp+tor@gool", "auto@wg-noize".
// Without one the variant chosen in the menu / config for that mode is used.
func (c *Controller) Start(spec string) error {
	raw, v := config.SplitMode(spec)
	mode := config.NormMode(raw)
	if mode == "" {
		return core.Wrap(ErrUnknownMode, fmt.Sprintf("unknown mode (use one of: %s)", strings.Join(config.AllModes, ", ")))
	}
	variant := c.cfg.VariantFor(mode)
	if v != "" {
		if variant = config.NormVariant(v); variant == "" {
			return core.Wrap(ErrUnknownVariant, fmt.Sprintf("unknown WARP variant %q (use one of: %s)", v, strings.Join(config.WarpVariants, ", ")))
		}
	} else if c.cfg.ModeVariant != "" {
		variant, c.cfg.ModeVariant = c.cfg.ModeVariant, "" // from -variant / "mode": "warp@x", first start only
	}
	if err := Preflight(c.cfg, mode, variant); err != nil {
		return err
	}
	c.Stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	bs, pin, err := BackendsFor(c.cfg, mode, variant)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(c.cfg.Listen, strconv.Itoa(c.cfg.Port)))
	if err != nil {
		return core.Wrap(ErrPortInUse, fmt.Sprintf("cannot listen on port %d (already in use?): %v", c.cfg.Port, err))
	}
	ctx, cancel := context.WithCancel(c.appCtx)
	m := core.NewManager(core.Options{
		Verbose:        func() bool { return c.cfg.Verbose },
		HealthURLs:     c.cfg.HealthURLs,
		HealthInterval: time.Duration(c.cfg.HealthInterval) * time.Second,
		Pin:            pin,
	}, bs)
	in := &inbound.Server{Dialer: m, Auth: inbound.Auth{Username: c.cfg.Username, Password: c.cfg.Password}}
	c.wg.Add(2)
	go func() { defer c.wg.Done(); m.Run(ctx) }()
	go func() { defer c.wg.Done(); in.Serve(ctx, ln) }()
	c.mgr, c.mode, c.variant, c.cancel = m, mode, variant, cancel
	c.cfg.LastMode = mode
	c.cfg.SaveSettings()
	if config.ModeUsesWarp(mode) {
		log.Infof("%s [WARP: %s] - proxy on %s:%d (SOCKS5 + HTTP)", config.ModeLabel(mode), config.VariantName(variant), c.cfg.Listen, c.cfg.Port)
	} else {
		log.Infof("%s - proxy on %s:%d (SOCKS5 + HTTP)", config.ModeLabel(mode), c.cfg.Listen, c.cfg.Port)
	}
	return nil
}

// Stop shuts the running mode down completely (engines, helper programs, open connections and
// the proxy port).
func (c *Controller) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel, c.mgr, c.mode, c.variant = nil, nil, "", ""
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	c.wg.Wait()
	log.Infof("stopped")
}

func (c *Controller) Running() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mgr != nil, c.mode
}

// RunVariant is the WARP variant the running mode was started with ("" when stopped).
func (c *Controller) RunVariant() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.variant
}

// Switch changes the active engine inside the running mode (auto mode only, in practice).
func (c *Controller) Switch(backend string) error {
	c.mu.Lock()
	m := c.mgr
	c.mu.Unlock()
	if m == nil {
		return ErrNotRunning
	}
	return m.SetMode(backend)
}

func (c *Controller) Status() core.Status {
	c.mu.Lock()
	m, mode, variant := c.mgr, c.mode, c.variant
	c.mu.Unlock()
	if m == nil {
		return core.Status{Version: c.info.Version, LastMode: c.cfg.LastMode, Port: c.cfg.Port, Backends: []core.BackendStatus{}}
	}
	st := m.Status()
	st.Version = c.info.Version
	st.Running = true
	st.RunMode = mode
	st.Variant = variant
	st.LastMode = c.cfg.LastMode
	st.Port = c.cfg.Port
	return st
}

// Variants lists the WARP variants and whether each can run here (GET /variants).
func (c *Controller) Variants() []api.Variant {
	var out []api.Variant
	for _, v := range config.WarpVariants {
		out = append(out, api.Variant{Name: v, Label: config.VariantLabels[v], Available: backends.VariantAvailable(c.cfg, v)})
	}
	return out
}

// Test sends real requests through the proxy and reports what happened.
func (c *Controller) Test() string {
	c.mu.Lock()
	m, mode, variant := c.mgr, c.mode, c.variant
	c.mu.Unlock()
	if m == nil {
		return ErrNotRunning.Error()
	}
	host := c.cfg.Listen
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(c.cfg.Port))}
	if c.cfg.Username != "" {
		u.User = url.UserPassword(c.cfg.Username, c.cfg.Password)
	}
	cl := &http.Client{
		Timeout:   25 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true},
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "mode: %s\n", config.ModeLabel(mode))
	if config.ModeUsesWarp(mode) && variant != "" {
		fmt.Fprintf(&sb, "WARP variant: %s\n", config.VariantName(variant))
	}
	t0 := time.Now()
	resp, err := cl.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		fmt.Fprintf(&sb, "HTTPS test FAILED: %v\n", err)
	} else {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		fmt.Fprintf(&sb, "HTTPS test OK in %d ms\n", time.Since(t0).Milliseconds())
		for _, l := range strings.Split(string(b), "\n") {
			for _, k := range []string{"ip=", "loc=", "warp="} {
				if strings.HasPrefix(l, k) {
					fmt.Fprintf(&sb, "  exit %s\n", strings.TrimSpace(l))
				}
			}
		}
	}
	for _, b := range m.Status().Backends {
		fmt.Fprintf(&sb, "  [%s%s] ready=%v healthy=%v latency=%dms", b.Name, orDefault(" "+b.Variant, ""), b.Ready, b.Healthy, b.LatencyMS)
		if b.Error != "" {
			fmt.Fprintf(&sb, "  last error: %s", b.Error)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// Info returns the program name and version.
func (c *Controller) Info() Info { return c.info }

var _ api.Controller = (*Controller)(nil)
