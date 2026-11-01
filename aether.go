package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AetherWarp runs the Aether program (CluvexStudio/Aether) as the WARP engine. Aether is where
// MASQUE (HTTP/3 and HTTP/2), gool, WARP-in-WARP, MASQUE-in-MASQUE and the handshake
// obfuscation ("noize") live; the built-in Go WireGuard in warp.go cannot do any of those.
//
// It is started with every question answered by a flag (so it never waits for a keyboard) and
// serves a private SOCKS5 port on 127.0.0.1. Aether opens that port only after its own
// end-to-end data check passed, and we confirm it with a real HTTP request before Ready().
type AetherWarp struct {
	cfg     *Config
	variant string
	port    int
	ready   atomic.Bool
	err     atomic.Value

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewAetherWarp(cfg *Config, variant string) *AetherWarp {
	return &AetherWarp{cfg: cfg, variant: variant}
}

func (a *AetherWarp) Name() string      { return "warp" }
func (a *AetherWarp) Variant() string   { return a.variant }
func (a *AetherWarp) SupportsUDP() bool { return true }
func (a *AetherWarp) Ready() bool       { return a.ready.Load() }
func (a *AetherWarp) LastError() string { s, _ := a.err.Load().(string); return s }

func aetherBin(cfg *Config) string { return findBinary(cfg.Aether.Bin, "aether") }

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func aetherDir(cfg *Config) string { return filepath.Join(cfg.DataDir, "aether") }

// aetherIdentityFlags points Aether's identity files into our data directory.
func aetherIdentityFlags(cfg *Config) []string {
	d := aetherDir(cfg)
	return []string{
		"--config", filepath.Join(d, "aether.toml"),
		"--wg-config", filepath.Join(d, "aether.toml"),
		"--masque-config", filepath.Join(d, "aether-masque.toml"),
	}
}

func (a *AetherWarp) args() []string {
	cfg := a.cfg
	args := []string{"--bind", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.port))}
	switch a.variant {
	case "masque":
		args = append(args, "--masque", "--h3")
	case "masque-h2":
		args = append(args, "--masque", "--h2")
	case "gool":
		args = append(args, "--gool")
	case "gool-classic":
		args = append(args, "--gool-classic")
	case "mim":
		args = append(args, "--mim")
	case "wg-noize":
		args = append(args, "--wg")
	}
	args = append(args, aetherIdentityFlags(cfg)...)
	if s := strings.TrimSpace(cfg.Aether.Scan); s != "" {
		args = append(args, "--scan", s)
	}
	switch cfg.Aether.IP {
	case "6":
		args = append(args, "-6")
	case "both":
		args = append(args, "--dual")
	default:
		args = append(args, "-4")
	}
	noize := strings.TrimSpace(cfg.Aether.Noize)
	if noize == "" && a.variant == "wg-noize" {
		noize = "gfw"
	}
	if noize != "" {
		args = append(args, "--noize", noize)
	}
	if cfg.Aether.Fragment {
		args = append(args, "--fragment")
	}
	args = append(args, "--quick-reconnect")
	if cfg.Verbose {
		args = append(args, "--log-level", "debug")
	} else {
		args = append(args, "--log-level", "info")
	}
	return args
}

func (a *AetherWarp) Start(ctx context.Context) error {
	bin := aetherBin(a.cfg)
	if bin == "" {
		return errors.New("aether" + exeSuffix() + " was not found next to clubconnect (or set its path in Settings); it is needed for MASQUE / gool / mim / noize")
	}
	a.port = freePort()
	if a.port == 0 {
		return errors.New("no free local port for aether")
	}
	if err := os.MkdirAll(aetherDir(a.cfg), 0o700); err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	a.mu.Lock()
	a.cancel, a.done = cancel, done
	a.mu.Unlock()
	p := &proc{
		name:    "warp/" + a.variant,
		bin:     bin,
		args:    a.args(),
		onStart: func() { a.ready.Store(false) },
		onLine:  a.handleLine,
		onExit:  func() { a.ready.Store(false) },
	}
	log.Printf("[warp/%s] starting aether (first run registers a free WARP identity; scanning for an endpoint can take 10-40 s)", a.variant)
	go func() {
		defer close(done)
		p.run(cctx)
	}()
	go a.watch(cctx)
	return nil
}

func (a *AetherWarp) Stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.cancel, a.done = nil, nil
	a.mu.Unlock()
	a.ready.Store(false)
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func (a *AetherWarp) handleLine(line string) {
	line = strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
	if line == "" {
		return
	}
	low := strings.ToLower(line)
	bad := strings.Contains(line, "[!]") || strings.Contains(low, "error") || strings.Contains(low, "fail") ||
		strings.Contains(low, "refused") || strings.Contains(low, "timed out") || strings.Contains(low, "blocked")
	if bad {
		msg := line
		if len(msg) > 300 {
			msg = msg[:300]
		}
		a.err.Store(msg)
	}
	if a.cfg.Verbose || strings.Contains(line, "[+]") || strings.Contains(line, "[!]") || strings.Contains(low, "error") {
		log.Printf("[warp/%s] %s", a.variant, line)
	}
}

// watch decides Ready(): the port must answer a real request through the tunnel.
func (a *AetherWarp) watch(ctx context.Context) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.port))
	fails := 0
	for ctx.Err() == nil {
		wait := 700 * time.Millisecond
		if a.ready.Load() {
			wait = 12 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		ok := probeSocks(pctx, addr)
		cancel()
		switch {
		case ok:
			fails = 0
			if !a.ready.Load() {
				a.err.Store("")
				log.Printf("[warp/%s] tunnel is up", a.variant)
			}
			a.ready.Store(true)
		case a.ready.Load():
			if fails++; fails >= 3 {
				a.ready.Store(false)
				fails = 0
				log.Printf("[warp/%s] tunnel stopped answering", a.variant)
			}
		}
	}
}

// probeSocks sends a real HTTP request through a SOCKS5 proxy and checks it got an answer.
func probeSocks(ctx context.Context, addr string) bool {
	c, err := socks5Dial(ctx, addr, "cp.cloudflare.com:80")
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	if _, err := c.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nConnection: close\r\n\r\n")); err != nil {
		return false
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(c, buf); err != nil {
		return false
	}
	return strings.HasPrefix(string(buf), "HTTP/1.")
}

func (a *AetherWarp) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !a.ready.Load() {
		return nil, errors.New("warp/" + a.variant + " is not connected")
	}
	return socks5Dial(ctx, fmt.Sprintf("127.0.0.1:%d", a.port), addr)
}

func (a *AetherWarp) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if !a.ready.Load() {
		return nil, errors.New("warp/" + a.variant + " is not connected")
	}
	return socks5UDPDial(ctx, fmt.Sprintf("127.0.0.1:%d", a.port), addr)
}
