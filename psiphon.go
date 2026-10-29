package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
)

// Psiphon runs the official tunnel-core console client. Club Connect writes the whole
// client configuration itself, so nothing has to be supplied by the user.
type Psiphon struct {
	cfg   *Config
	port  int
	ready atomic.Bool
	err   atomic.Value
}

func NewPsiphon(cfg *Config) *Psiphon { return &Psiphon{cfg: cfg} }

func (p *Psiphon) Name() string      { return "psiphon" }
func (p *Psiphon) SupportsUDP() bool { return false }
func (p *Psiphon) Ready() bool       { return p.ready.Load() }
func (p *Psiphon) LastError() string { s, _ := p.err.Load().(string); return s }
func (p *Psiphon) Stop()             {}

func (p *Psiphon) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !p.ready.Load() {
		return nil, errors.New("psiphon not connected")
	}
	return socks5Dial(ctx, fmt.Sprintf("127.0.0.1:%d", p.port), addr)
}

func (p *Psiphon) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.New("psiphon has no UDP")
}

// The protocol names are Psiphon's own. In-proxy protocols are left out: they need a broker
// and are the slowest to establish.
var psiphonProtocols = []string{
	"SSH", "OSSH", "TLS-OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
	"UNFRONTED-MEEK-SESSION-TICKET-OSSH", "QUIC-OSSH", "SHADOWSOCKS-OSSH",
	"FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH", "FRONTED-MEEK-QUIC-OSSH",
	"FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-CDN-HTTP-OSSH", "FRONTED-MEEK-CDN-QUIC-OSSH",
}

func platformName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows_ClubConnect"
	case "darwin":
		return "macOS_ClubConnect"
	}
	return "Linux_ClubConnect" // android binaries run as linux
}

func (p *Psiphon) Start(ctx context.Context) error {
	bin := findBinary(p.cfg.Psiphon.Bin, "psiphon-tunnel-core", "psiphon")
	if bin == "" {
		return errors.New("psiphon-tunnel-core binary not found (the release zip ships it next to clubconnect)")
	}
	dir := filepath.Join(p.cfg.DataDir, "psiphon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p.port = freePort()
	conf := map[string]any{
		"PropagationChannelId":                      psiphonPropagationChannel,
		"SponsorId":                                 psiphonSponsor,
		"ClientPlatform":                            platformName(),
		"ClientVersion":                             "1",
		"RemoteServerListURLs":                      []map[string]any{{"URL": base64.StdEncoding.EncodeToString([]byte(psiphonServerListURL))}},
		"RemoteServerListSignaturePublicKey":        psiphonServerListKey,
		"DataRootDirectory":                         dir,
		"LocalSocksProxyPort":                       p.port,
		"DisableLocalHTTPProxy":                     true,
		"EmitDiagnosticNotices":                     true,
		"LimitTunnelProtocols":                      psiphonProtocols,
		"InproxyTunnelProtocolPreferProbability":    0.0,
		"InproxyTunnelProtocolSelectionProbability": 0.0,
	}
	if r := strings.ToUpper(strings.TrimSpace(p.cfg.Psiphon.Region)); len(r) == 2 {
		conf["EgressRegion"] = r
	}
	b, _ := json.MarshalIndent(conf, "", "  ")
	cfgPath := filepath.Join(dir, "client.config")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		return err
	}
	pr := &proc{
		name: "psiphon", bin: bin,
		args: []string{"-config", cfgPath, "-dataRootDirectory", dir},
		onLine: func(line string) {
			var n struct {
				Type string `json:"noticeType"`
				Data struct {
					Count   int    `json:"count"`
					Message string `json:"message"`
				} `json:"data"`
			}
			if json.Unmarshal([]byte(line), &n) != nil {
				return
			}
			switch n.Type {
			case "Tunnels":
				if n.Data.Count > 0 && !p.ready.Load() {
					log.Printf("[psiphon] tunnel established")
				}
				p.ready.Store(n.Data.Count > 0)
			case "Alert", "Error":
				p.err.Store(n.Data.Message)
			}
		},
		onExit: func() { p.ready.Store(false) },
	}
	go pr.run(ctx)
	return nil
}
