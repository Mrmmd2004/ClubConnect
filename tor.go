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
	"strings"
	"sync/atomic"
)

// Tor runs the system/bundled tor with bridges (obfs4, snowflake, meek, webtunnel).
// Default bridges are built in, so no configuration is needed.
type Tor struct {
	cfg   *Config
	port  int
	ready atomic.Bool
	err   atomic.Value
}

func NewTor(cfg *Config) *Tor { return &Tor{cfg: cfg} }

func (t *Tor) Name() string      { return "tor" }
func (t *Tor) SupportsUDP() bool { return false }
func (t *Tor) Ready() bool       { return t.ready.Load() }
func (t *Tor) LastError() string { s, _ := t.err.Load().(string); return s }
func (t *Tor) Stop()             {}

func (t *Tor) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !t.ready.Load() {
		return nil, errors.New("tor not bootstrapped")
	}
	return socks5Dial(ctx, fmt.Sprintf("127.0.0.1:%d", t.port), addr)
}

func (t *Tor) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.New("tor has no UDP")
}

func (t *Tor) Start(ctx context.Context) error {
	bin := findBinary(t.cfg.Tor.Bin, "tor")
	if bin == "" {
		return errors.New("tor binary not found")
	}
	lyre := findBinary("", "lyrebird", "obfs4proxy")
	snow := findBinary("", "snowflake-client")

	// pluggable transports available -> which bridge lines are usable
	transports := map[string]string{}
	if lyre != "" {
		for _, n := range []string{"obfs4", "meek_lite", "webtunnel"} {
			transports[n] = lyre
		}
	}
	if snow != "" {
		transports["snowflake"] = snow
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
		return errors.New("tor needs lyrebird/obfs4proxy or snowflake-client next to it (shipped in the release zip)")
	}
	rand.Shuffle(len(usable), func(i, j int) { usable[i], usable[j] = usable[j], usable[i] })
	if len(usable) > 8 {
		usable = usable[:8]
	}

	dir := filepath.Join(t.cfg.DataDir, "tor")
	os.MkdirAll(filepath.Join(dir, "data"), 0o700)
	t.port = freePort()
	var sb strings.Builder
	fmt.Fprintf(&sb, "SocksPort 127.0.0.1:%d\nDataDirectory %s\nAvoidDiskWrites 1\nSafeLogging 1\nLog notice stdout\nUseBridges 1\n",
		t.port, filepath.Join(dir, "data"))
	byPath := map[string][]string{}
	for tr, path := range transports {
		byPath[path] = append(byPath[path], tr)
	}
	for path, trs := range byPath {
		fmt.Fprintf(&sb, "ClientTransportPlugin %s exec %s\n", strings.Join(trs, ","), path)
	}
	for _, l := range usable {
		fmt.Fprintf(&sb, "Bridge %s\n", l)
	}
	rc := filepath.Join(dir, "torrc")
	if err := os.WriteFile(rc, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	pr := &proc{
		name: "tor", bin: bin, args: []string{"-f", rc},
		onLine: func(line string) {
			if strings.Contains(line, "Bootstrapped 100%") {
				log.Printf("[tor] bootstrapped")
				t.ready.Store(true)
			} else if strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
				t.err.Store(line)
			}
		},
		onExit: func() { t.ready.Store(false) },
	}
	go pr.run(ctx)
	return nil
}
