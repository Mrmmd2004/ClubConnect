package backends

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
	"clubconnect/internal/proc"
	"clubconnect/internal/socks"
)

// AetherWarp runs the Aether program (CluvexStudio/Aether) as the WARP engine. Aether is where
// MASQUE (HTTP/3 and HTTP/2), gool, WARP-in-WARP, MASQUE-in-MASQUE and the handshake
// obfuscation ("noize") live; the built-in Go WireGuard in warp.go cannot do any of those.
// Aether is written in Rust, so it cannot be linked into this program: the release build
// embeds its binary in clubconnect (see internal/bundle) and it is unpacked on start.
//
// It is started with every question answered by a flag (so it never waits for a keyboard) and
// serves a private SOCKS5 port on 127.0.0.1. Aether opens that port only after its own
// end-to-end data check passed, and we confirm it with a real HTTP request before Ready().
type AetherWarp struct {
	core.Base
	cfg     *config.Config
	variant string
	port    atomic.Int32
	log     logx.Logger
}

func NewAetherWarp(cfg *config.Config, variant string) *AetherWarp {
	return &AetherWarp{cfg: cfg, variant: variant, log: logx.For("warp/" + variant)}
}

func (a *AetherWarp) Name() string      { return "warp" }
func (a *AetherWarp) Variant() string   { return a.variant }
func (a *AetherWarp) SupportsUDP() bool { return true }

func aetherDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "aether") }

// aetherIdentityFlags points Aether's identity files into our data directory.
func aetherIdentityFlags(cfg *config.Config) []string {
	d := aetherDir(cfg)
	return []string{
		"--config", filepath.Join(d, "aether.toml"),
		"--wg-config", filepath.Join(d, "aether.toml"),
		"--masque-config", filepath.Join(d, "aether-masque.toml"),
	}
}

func (a *AetherWarp) args() []string {
	cfg := a.cfg
	args := []string{"--bind", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(a.port.Load())))}
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

func (a *AetherWarp) Start(parent context.Context) error {
	bin := AetherBin(a.cfg)
	if bin == "" {
		return errors.New("aether" + proc.ExeSuffix() + " was not found (it is normally built into clubconnect; or set its path in Settings); it is needed for MASQUE / gool / mim / noize")
	}
	port := proc.FreePort()
	if port == 0 {
		return errors.New("no free local port for aether")
	}
	a.port.Store(int32(port))
	if err := os.MkdirAll(aetherDir(a.cfg), 0o700); err != nil {
		return err
	}
	ctx := a.Begin(parent)
	p := &proc.Process{
		Name:    "warp/" + a.variant,
		Bin:     bin,
		Args:    a.args(),
		OnStart: func() { a.SetReady(false) },
		OnLine:  a.handleLine,
		OnExit:  func(proc.ExitInfo) { a.SetReady(false) },
	}
	a.log.Infof("starting aether (first run registers a free WARP identity; scanning for an endpoint can take 10-40 s)")
	a.Spawn(func() { p.Run(ctx) })
	a.Go(func() { a.watch(ctx) })
	return nil
}

func (a *AetherWarp) Stop() {
	a.End(5 * time.Second)
	if p := int(a.port.Swap(0)); p != 0 {
		proc.ReleasePort(p)
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
		a.SetError(msg)
	}
	if a.cfg.Verbose || strings.Contains(line, "[+]") || strings.Contains(line, "[!]") || strings.Contains(low, "error") {
		a.log.Infof("%s", line)
	}
}

// watch decides Ready(): the port must answer a real request through the tunnel.
func (a *AetherWarp) watch(ctx context.Context) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(a.port.Load())))
	fails := 0
	for ctx.Err() == nil {
		wait := 700 * time.Millisecond
		if a.Ready() {
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
			if !a.Ready() {
				a.SetError("")
				a.log.Infof("tunnel is up")
			}
			a.SetReady(true)
		case a.Ready():
			if fails++; fails >= 3 {
				a.SetReady(false)
				fails = 0
				a.log.Infof("tunnel stopped answering")
			}
		}
	}
}

// probeSocks sends a real HTTP request through a SOCKS5 proxy and checks it got an answer.
func probeSocks(ctx context.Context, addr string) bool {
	c, err := socks.Dial(ctx, addr, "cp.cloudflare.com:80")
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

func (a *AetherWarp) upstream() string {
	return fmt.Sprintf("127.0.0.1:%d", a.port.Load())
}

func (a *AetherWarp) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !a.Ready() {
		return nil, core.NotReady("warp/" + a.variant + " is not connected")
	}
	return socks.Dial(ctx, a.upstream(), addr)
}

func (a *AetherWarp) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	if !a.Ready() {
		return nil, core.NotReady("warp/" + a.variant + " is not connected")
	}
	return socks.UDPDial(ctx, a.upstream(), addr)
}
