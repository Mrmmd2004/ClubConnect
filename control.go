package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The modes. Nothing runs until one of them is started (menu, -mode flag or the API).
var allModes = []string{"auto", "warp", "psiphon", "tor", "warp+psiphon", "warp+tor"}

var modeLabels = map[string]string{
	"auto":         "Auto (best of WARP / Psiphon / Tor)",
	"warp":         "WARP only",
	"psiphon":      "Psiphon only",
	"tor":          "Tor only",
	"warp+psiphon": "WARP -> Psiphon",
	"warp+tor":     "WARP -> Tor",
}

func modeLabel(m string) string {
	if l, ok := modeLabels[m]; ok {
		return l
	}
	return m
}

// splitMode separates an optional WARP variant: "warp@masque" -> ("warp", "masque").
func splitMode(s string) (mode, variant string) {
	if i := strings.IndexByte(s, '@'); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return strings.TrimSpace(s), ""
}

// modeUsesWarp tells whether a mode has a WARP engine whose variant can be chosen.
func modeUsesWarp(mode string) bool {
	return mode == "auto" || mode == "warp" || mode == "warp+psiphon" || mode == "warp+tor"
}

// normMode accepts a few spellings ("Cloudflare-Tor", "cf->psiphon") and returns "" if unknown.
func normMode(s string) string {
	s = strings.NewReplacer("cloudflare", "warp", "cf", "warp", " ", "", "->", "+", ">", "+", "-", "+", "_", "+").
		Replace(strings.ToLower(strings.TrimSpace(s)))
	for _, m := range allModes {
		if s == m {
			return m
		}
	}
	return ""
}

// Controller starts and stops the engines on demand and owns the proxy listener.
type Controller struct {
	cfg    *Config
	appCtx context.Context

	mu     sync.Mutex
	mgr     *Manager
	mode    string
	variant string
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

func NewController(ctx context.Context, cfg *Config) *Controller {
	return &Controller{cfg: cfg, appCtx: ctx}
}

func (c *Controller) backendsFor(mode, variant string) ([]Backend, string, error) {
	switch mode {
	case "auto":
		var bs []Backend
		for _, n := range c.cfg.Order {
			switch strings.TrimSpace(n) {
			case "warp":
				bs = append(bs, newWarpBackend(c.cfg, variant))
			case "psiphon":
				bs = append(bs, NewPsiphon(c.cfg))
			case "tor":
				bs = append(bs, NewTor(c.cfg))
			default:
				return nil, "", fmt.Errorf("unknown backend %q in order", n)
			}
		}
		if len(bs) == 0 {
			return nil, "", errors.New("no backends enabled")
		}
		return bs, "", nil
	case "warp":
		return []Backend{newWarpBackend(c.cfg, variant)}, "warp", nil
	case "psiphon":
		return []Backend{NewPsiphon(c.cfg)}, "psiphon", nil
	case "tor":
		return []Backend{NewTor(c.cfg)}, "tor", nil
	case "warp+psiphon":
		return []Backend{NewChainPsiphon(c.cfg, variant)}, "warp+psiphon", nil
	case "warp+tor":
		return []Backend{NewChainTor(c.cfg, variant)}, "warp+tor", nil
	}
	return nil, "", fmt.Errorf("unknown mode %q", mode)
}

// preflight refuses a manual mode whose program is missing, so the failure is shown at once.
func (c *Controller) preflight(mode, variant string) error {
	if modeUsesWarp(mode) && variantNeedsAether(variant) && aetherBin(c.cfg) == "" {
		return fmt.Errorf("WARP variant %q needs aether%s next to clubconnect (or set its path in Settings); choose the built-in \"wg\" or \"auto\" instead", variant, exeSuffix())
	}
	if (mode == "psiphon" || mode == "warp+psiphon") && psiphonBin(c.cfg) == "" {
		return errors.New("psiphon-tunnel-core was not found next to clubconnect (or set its path in Settings)")
	}
	if (mode == "tor" || mode == "warp+tor") && torBin(c.cfg) == "" {
		return errors.New("tor was not found: put tor.exe next to clubconnect, install Tor Browser, or set its path in Settings")
	}
	return nil
}

// Start stops whatever runs and starts the given mode.
// The mode may carry a WARP variant: "warp@masque", "warp+tor@gool", "auto@wg-noize".
// Without one the variant chosen in the menu / config for that mode is used.
func (c *Controller) Start(spec string) error {
	raw, v := splitMode(spec)
	mode := normMode(raw)
	if mode == "" {
		return fmt.Errorf("unknown mode (use one of: %s)", strings.Join(allModes, ", "))
	}
	variant := c.cfg.variantFor(mode)
	if v != "" {
		if variant = normVariant(v); variant == "" {
			return fmt.Errorf("unknown WARP variant %q (use one of: %s)", v, strings.Join(warpVariants, ", "))
		}
	} else if c.cfg.ModeVariant != "" {
		variant, c.cfg.ModeVariant = c.cfg.ModeVariant, "" // from -variant / "mode": "warp@x", first start only
	}
	if err := c.preflight(mode, variant); err != nil {
		return err
	}
	c.Stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	bs, pin, err := c.backendsFor(mode, variant)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(c.cfg.Listen, strconv.Itoa(c.cfg.Port)))
	if err != nil {
		return fmt.Errorf("cannot listen on port %d (already in use?): %v", c.cfg.Port, err)
	}
	ctx, cancel := context.WithCancel(c.appCtx)
	m := NewManager(c.cfg, bs)
	if pin != "" {
		m.mode.Store(pin)
	}
	in := &Inbound{m: m, cfg: c.cfg}
	c.wg.Add(2)
	go func() { defer c.wg.Done(); m.Run(ctx) }()
	go func() { defer c.wg.Done(); in.serve(ctx, ln) }()
	c.mgr, c.mode, c.variant, c.cancel = m, mode, variant, cancel
	c.cfg.LastMode = mode
	c.cfg.saveSettings()
	if modeUsesWarp(mode) {
		log.Printf("[core] %s [WARP: %s] - proxy on %s:%d (SOCKS5 + HTTP)", modeLabel(mode), variantName(variant), c.cfg.Listen, c.cfg.Port)
	} else {
		log.Printf("[core] %s - proxy on %s:%d (SOCKS5 + HTTP)", modeLabel(mode), c.cfg.Listen, c.cfg.Port)
	}
	return nil
}

// Stop shuts the running mode down completely (engines, helper programs and the proxy port).
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
	log.Printf("[core] stopped")
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
		return errors.New("not running - start a mode first")
	}
	return m.SetMode(backend)
}

func (c *Controller) Status() status {
	c.mu.Lock()
	m, mode := c.mgr, c.mode
	c.mu.Unlock()
	if m == nil {
		return status{Version: Version, LastMode: c.cfg.LastMode, Port: c.cfg.Port, Backends: []backendStatus{}}
	}
	st := m.Status()
	st.Running = true
	st.RunMode = mode
	st.Variant = c.RunVariant()
	st.LastMode = c.cfg.LastMode
	st.Port = c.cfg.Port
	return st
}

// Test sends real requests through the proxy and reports what happened.
func (c *Controller) Test() string {
	c.mu.Lock()
	m, mode := c.mgr, c.mode
	c.mu.Unlock()
	if m == nil {
		return "not running - start a mode first"
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
	fmt.Fprintf(&sb, "mode: %s\n", modeLabel(mode))
	if v := c.RunVariant(); modeUsesWarp(mode) && v != "" {
		fmt.Fprintf(&sb, "WARP variant: %s\n", variantName(v))
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
