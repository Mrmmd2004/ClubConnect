package backends

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
	"clubconnect/internal/proc"
	"clubconnect/internal/socks"
)

var plog = logx.For("psiphon")

// Psiphon runs the tunnel-core console client. Club Connect writes the whole client
// configuration itself, so nothing has to be supplied by the user.
//
// Upstream is set in "Cloudflare -> Psiphon" mode: Psiphon then dials every connection
// through the WARP gate (a local SOCKS5 port), so only TCP protocols are offered.
type Psiphon struct {
	core.Base
	cfg      *config.Config
	Upstream string // "socks5://127.0.0.1:port" or empty
	port     atomic.Int32

	mu        sync.Mutex
	dir       string
	cfgPath   string
	profile   int // 0 = full list, 1 = plain list, 2 = no list (only when not chained)
	tail      []string
	t0        time.Time
	gotTunnel bool
}

func NewPsiphon(cfg *config.Config) *Psiphon { return &Psiphon{cfg: cfg} }

func (p *Psiphon) Name() string      { return "psiphon" }
func (p *Psiphon) SupportsUDP() bool { return false }

func (p *Psiphon) Stop() {
	p.End(5 * time.Second)
	if n := int(p.port.Swap(0)); n != 0 {
		proc.ReleasePort(n)
	}
}

func (p *Psiphon) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if !p.Ready() {
		return nil, core.NotReady("psiphon not connected")
	}
	return socks.Dial(ctx, fmt.Sprintf("127.0.0.1:%d", p.port.Load()), addr)
}

func (p *Psiphon) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, core.NoUDP("psiphon has no UDP")
}

// Protocol names are Psiphon's own. In-proxy protocols are left out: they need a broker and are
// the slowest to establish. The FRONTED-MEEK-CDN-* names only exist in the Psiphon fork that
// Aether uses (CluvexStudio, branch shirokhorshid); a stock tunnel-core refuses a config that
// names them and exits at once. That is why the list is tried in levels (see handleExit).
var (
	psiCDN      = []string{"FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-CDN-HTTP-OSSH", "FRONTED-MEEK-CDN-QUIC-OSSH"}
	psiDirect   = []string{"SSH", "OSSH", "TLS-OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH", "UNFRONTED-MEEK-SESSION-TICKET-OSSH", "SHADOWSOCKS-OSSH"}
	psiStandard = []string{
		"SSH", "OSSH", "TLS-OSSH", "UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH",
		"UNFRONTED-MEEK-SESSION-TICKET-OSSH", "QUIC-OSSH", "SHADOWSOCKS-OSSH",
		"FRONTED-MEEK-OSSH", "FRONTED-MEEK-HTTP-OSSH", "FRONTED-MEEK-QUIC-OSSH",
	}
)

func withoutQUIC(in []string) []string {
	var out []string
	for _, n := range in {
		if !strings.Contains(n, "QUIC") {
			out = append(out, n)
		}
	}
	return out
}

// PsiphonProtocols returns the LimitTunnelProtocols list for a level; nil = do not limit.
func PsiphonProtocols(profile int, style string, chained bool) []string {
	var l []string
	switch {
	case profile >= 2 && !chained:
		return nil
	case profile >= 1:
		l = psiStandard
	case style == "cdn":
		l = psiCDN
	case style == "direct":
		l = psiDirect
	default:
		l = append(append([]string{}, psiStandard...), psiCDN...)
	}
	if chained {
		l = withoutQUIC(l) // a SOCKS5 hop cannot carry UDP
	}
	return l
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

func (p *Psiphon) writeConfig() error {
	p.mu.Lock()
	profile, dir, cfgPath := p.profile, p.dir, p.cfgPath
	p.mu.Unlock()
	chained := p.Upstream != ""
	conf := map[string]any{
		"PropagationChannelId":                      psiphonPropagationChannel,
		"SponsorId":                                 psiphonSponsor,
		"ClientPlatform":                            platformName(),
		"ClientVersion":                             "1",
		"RemoteServerListURLs":                      []map[string]any{{"URL": base64.StdEncoding.EncodeToString([]byte(psiphonServerListURL))}},
		"RemoteServerListSignaturePublicKey":        psiphonServerListKey,
		"DataRootDirectory":                         dir,
		"LocalSocksProxyPort":                       int(p.port.Load()),
		"DisableLocalHTTPProxy":                     true,
		"EmitDiagnosticNotices":                     true,
		"InproxyTunnelProtocolPreferProbability":    0.0,
		"InproxyTunnelProtocolSelectionProbability": 0.0,
	}
	if l := PsiphonProtocols(profile, p.cfg.Psiphon.Style, chained); len(l) > 0 {
		conf["LimitTunnelProtocols"] = l
	}
	if profile == 0 {
		conf["FrontedMeekCDNScanUseBuiltInSpec"] = true
	}
	if chained {
		conf["UpstreamProxyURL"] = p.Upstream
		conf["DisableTactics"] = true
	}
	if r := strings.ToUpper(strings.TrimSpace(p.cfg.Psiphon.Region)); len(r) == 2 {
		conf["EgressRegion"] = r
	}
	b, _ := json.MarshalIndent(conf, "", "  ")
	return os.WriteFile(cfgPath, b, 0o600)
}

func (p *Psiphon) remember(s string) {
	if len(s) > 300 {
		s = s[:300]
	}
	p.mu.Lock()
	p.tail = append(p.tail, s)
	if len(p.tail) > 8 {
		p.tail = p.tail[len(p.tail)-8:]
	}
	p.mu.Unlock()
}

func (p *Psiphon) handleLine(line string) {
	var n struct {
		Type string `json:"noticeType"`
		Data struct {
			Count   int    `json:"count"`
			Message string `json:"message"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(line), &n) != nil {
		p.remember(line) // plain text is most likely the reason it is about to exit
		return
	}
	switch n.Type {
	case "Tunnels":
		if n.Data.Count > 0 {
			p.mu.Lock()
			p.gotTunnel = true
			p.mu.Unlock()
			if !p.Ready() {
				plog.Infof("tunnel established")
			}
		}
		p.SetReady(n.Data.Count > 0)
	case "Alert", "Error":
		msg := n.Data.Message
		if msg == "" {
			msg = line
		}
		p.SetError(msg)
		p.remember(n.Type + ": " + msg)
	}
	if p.cfg.Verbose {
		plog.Infof("%s", line)
	}
}

// handleExit explains a process that dies right after launch (the log used to say only
// "process exited") and retries with a simpler protocol list.
func (p *Psiphon) handleExit(proc.ExitInfo) {
	p.SetReady(false)
	p.mu.Lock()
	early := !p.gotTunnel && time.Since(p.t0) < 25*time.Second
	tail := strings.Join(p.tail, " | ")
	limit := 2
	if p.Upstream != "" {
		limit = 1
	}
	changed := false
	if early && p.profile < limit {
		p.profile++
		changed = true
	}
	level := p.profile
	p.mu.Unlock()
	if !early {
		return
	}
	if tail == "" {
		tail = "(the program printed nothing)"
	}
	plog.Infof("stopped right after start: %s", tail)
	p.SetError("exited at start: " + tail)
	if changed {
		plog.Infof("retrying with a simpler protocol list (level %d)", level)
		if err := p.writeConfig(); err != nil {
			plog.Infof("cannot rewrite config: %v", err)
		}
	}
}

func (p *Psiphon) Start(parent context.Context) error {
	bin := PsiphonBin(p.cfg)
	if bin == "" {
		return errors.New("psiphon-tunnel-core binary not found (it is normally built into clubconnect; or set its path in Settings)")
	}
	dir := filepath.Join(p.cfg.DataDir, "psiphon")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p.mu.Lock()
	p.dir = dir
	p.cfgPath = filepath.Join(dir, "client.config")
	p.profile = 0
	cfgPath := p.cfgPath
	p.mu.Unlock()
	p.port.Store(int32(proc.FreePort()))
	if err := p.writeConfig(); err != nil {
		return err
	}
	ctx := p.Begin(parent)
	pr := &proc.Process{
		Name: "psiphon", Bin: bin,
		Args: []string{"-config", cfgPath, "-dataRootDirectory", dir},
		OnStart: func() {
			p.mu.Lock()
			p.t0 = time.Now()
			p.gotTunnel = false
			p.tail = nil
			p.mu.Unlock()
		},
		OnLine: p.handleLine,
		OnExit: p.handleExit,
	}
	p.Spawn(func() { pr.Run(ctx) })
	return nil
}
