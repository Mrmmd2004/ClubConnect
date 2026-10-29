package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tor runs the system/bundled tor, with bridges (obfs4, snowflake, meek, webtunnel) or without.
// Default bridges are built in, so no configuration is needed.
//
// Upstream ("127.0.0.1:port") is set in "Cloudflare -> Tor" mode: tor then reaches its relays or
// bridges through the WARP gate. Snowflake needs UDP, so it is not offered in that mode.
type Tor struct {
	cfg      *Config
	Upstream string
	port     int
	ready    atomic.Bool
	err      atomic.Value

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewTor(cfg *Config) *Tor { return &Tor{cfg: cfg} }

func (t *Tor) Name() string      { return "tor" }
func (t *Tor) SupportsUDP() bool { return false }
func (t *Tor) Ready() bool       { return t.ready.Load() }
func (t *Tor) LastError() string { s, _ := t.err.Load().(string); return s }

func (t *Tor) Stop() {
	t.mu.Lock()
	cancel, done := t.cancel, t.done
	t.cancel, t.done = nil, nil
	t.mu.Unlock()
	t.ready.Store(false)
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

func (t *Tor) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !t.ready.Load() {
		return nil, errors.New("tor not bootstrapped")
	}
	return socks5Dial(ctx, fmt.Sprintf("127.0.0.1:%d", t.port), addr)
}

func (t *Tor) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.New("tor has no UDP")
}

// torBrowserDirs lists the places an installed Tor Browser keeps tor and its transports.
func torBrowserDirs() []string {
	var out []string
	add := func(base string) {
		out = append(out,
			filepath.Join(base, "Browser", "TorBrowser", "Tor"),
			filepath.Join(base, "Browser", "TorBrowser", "Tor", "PluggableTransports"))
	}
	switch runtime.GOOS {
	case "windows":
		if h := os.Getenv("USERPROFILE"); h != "" {
			add(filepath.Join(h, "Desktop", "Tor Browser"))
			add(filepath.Join(h, "Downloads", "Tor Browser"))
		}
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			add(filepath.Join(d, "Tor Browser"))
		}
		if d := os.Getenv("ProgramFiles"); d != "" {
			add(filepath.Join(d, "Tor Browser"))
		}
		if d := os.Getenv("ProgramFiles(x86)"); d != "" {
			add(filepath.Join(d, "Tor Browser"))
		}
	case "darwin":
		out = append(out,
			"/Applications/Tor Browser.app/Contents/MacOS/Tor",
			"/Applications/Tor Browser.app/Contents/MacOS/Tor/PluggableTransports")
	}
	return out
}

func torBin(cfg *Config) string {
	return findBinaryIn(cfg.Tor.Bin, torBrowserDirs(), "tor")
}

// ptDirs: where the transports (lyrebird, snowflake-client) may live next to a given tor.
func ptDirs(bin string) []string {
	d := filepath.Dir(bin)
	out := []string{
		d,
		filepath.Join(d, "PluggableTransports"),
		filepath.Join(d, "pluggable_transports"),
		filepath.Join(filepath.Dir(d), "pluggable_transports"),
	}
	return append(out, torBrowserDirs()...)
}

// plainPath: tor splits "ClientTransportPlugin ... exec <path>" on spaces, so a transport that
// lives in a folder like "Tor Browser" is copied to the data directory first.
func plainPath(p, dir string) string {
	if !strings.ContainsAny(p, " \t") {
		return p
	}
	dst := filepath.Join(dir, "pt", filepath.Base(p))
	if strings.ContainsAny(dst, " \t") {
		return p
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return p
	}
	os.MkdirAll(filepath.Dir(dst), 0o700)
	if os.WriteFile(dst, b, 0o700) != nil {
		return p
	}
	return dst
}

func (t *Tor) Start(ctx context.Context) error {
	bin := torBin(t.cfg)
	if bin == "" {
		return errors.New("tor binary not found: put tor (tor.exe) next to clubconnect, install Tor Browser, or set the path in Settings")
	}
	kind := strings.ToLower(strings.TrimSpace(t.cfg.Tor.Bridge))
	if kind == "" {
		kind = "auto"
	}
	chained := t.Upstream != ""
	dir := filepath.Join(t.cfg.DataDir, "tor")
	os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	t.port = freePort()

	var sb strings.Builder
	fmt.Fprintf(&sb, "SocksPort 127.0.0.1:%d\nDataDirectory \"%s\"\nAvoidDiskWrites 1\nSafeLogging 1\nLog notice stdout\n",
		t.port, filepath.ToSlash(filepath.Join(dir, "data")))
	if chained {
		fmt.Fprintf(&sb, "Socks5Proxy %s\n", t.Upstream)
	}

	if kind == "none" {
		log.Printf("[tor] starting without bridges (direct connection to the Tor network)")
	} else {
		extra := ptDirs(bin)
		lyre := findBinaryIn("", extra, "lyrebird", "obfs4proxy")
		snow := findBinaryIn("", extra, "snowflake-client")
		allowed := func(tr string) bool {
			if chained && tr == "snowflake" {
				return false
			}
			switch kind {
			case "obfs4":
				return tr == "obfs4"
			case "snowflake":
				return tr == "snowflake"
			case "meek":
				return tr == "meek_lite"
			case "webtunnel":
				return tr == "webtunnel"
			}
			return true
		}
		// transports that are installed and wanted
		transports := map[string]string{}
		if lyre != "" {
			lyre = plainPath(lyre, dir)
			for _, n := range []string{"obfs4", "meek_lite", "webtunnel"} {
				if allowed(n) {
					transports[n] = lyre
				}
			}
		}
		if snow != "" && allowed("snowflake") {
			transports["snowflake"] = plainPath(snow, dir)
		}

		var lines []string
		if f := t.cfg.Tor.BridgesFile; f != "" {
			if b, err := os.ReadFile(f); err == nil {
				lines = append(lines, strings.Split(string(b), "\n")...)
			}
		} else if b, err := os.ReadFile(filepath.Join(t.cfg.DataDir, "bridges.txt")); err == nil {
			lines = append(lines, strings.Split(string(b), "\n")...)
		}
		if len(lines) == 0 {
			lines = defaultBridges
		}
		var usable []string
		for _, l := range lines {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "Bridge "))
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if _, ok := transports[strings.Fields(l)[0]]; ok {
				usable = append(usable, l)
			}
		}
		if len(usable) == 0 {
			return fmt.Errorf("no usable %q bridge: tor needs lyrebird/obfs4proxy%s next to it, and bridges of that type", kind,
				map[bool]string{true: "", false: " or snowflake-client"}[chained])
		}
		rand.Shuffle(len(usable), func(i, j int) { usable[i], usable[j] = usable[j], usable[i] })
		if len(usable) > 8 {
			usable = usable[:8]
		}
		fmt.Fprintf(&sb, "UseBridges 1\n")
		byPath := map[string][]string{}
		for tr, path := range transports {
			byPath[path] = append(byPath[path], tr)
		}
		for path, trs := range byPath {
			fmt.Fprintf(&sb, "ClientTransportPlugin %s exec %s\n", strings.Join(trs, ","), filepath.ToSlash(path))
		}
		for _, l := range usable {
			fmt.Fprintf(&sb, "Bridge %s\n", l)
		}
	}

	rc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(rc, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	t.mu.Lock()
	t.cancel, t.done = cancel, done
	t.mu.Unlock()
	pr := &proc{
		name: "tor", bin: bin, args: []string{"-f", rc},
		onLine: func(line string) {
			if i := strings.Index(line, "Bootstrapped "); i >= 0 {
				rest := strings.TrimPrefix(line[i:], "Bootstrapped ")
				if j := strings.Index(rest, "%"); j >= 0 {
					rest = rest[:j]
				}
				n, _ := strconv.Atoi(strings.TrimSpace(rest))
				if n >= 100 {
					log.Printf("[tor] bootstrapped")
					t.ready.Store(true)
				} else if n%25 == 0 || t.cfg.Verbose {
					log.Printf("[tor] bootstrapping %d%%", n)
				}
				return
			}
			if strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
				t.err.Store(line)
				if t.cfg.Verbose {
					log.Printf("[tor] %s", line)
				}
			}
		},
		onExit: func() { t.ready.Store(false) },
	}
	go func() {
		pr.run(cctx)
		close(done)
	}()
	return nil
}
