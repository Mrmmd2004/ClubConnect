package backends

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
)

func TestMain(m *testing.M) {
	logx.InitWriter(io.Discard, slog.LevelError)
	os.Exit(m.Run())
}

func testCfg(t *testing.T) *config.Config {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Aether.Bin, c.Psiphon.Bin, c.Tor.Bin = "", "", ""
	return c
}

// fakeProgram puts an executable file called name into <DataDir>/bin, where the unpacked
// helpers live.
func fakeProgram(t *testing.T, c *config.Config, name string) string {
	dir := filepath.Join(c.DataDir, "bin")
	os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, name+exe())
	if err := os.WriteFile(p, []byte("#!/bin/sh\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// ---------- Psiphon ----------

func TestPsiphonProtocols(t *testing.T) {
	// a chained Psiphon must never be offered a UDP protocol
	for _, p := range []int{0, 1, 2} {
		for _, style := range []string{"auto", "cdn", "direct"} {
			for _, n := range PsiphonProtocols(p, style, true) {
				if strings.Contains(n, "QUIC") {
					t.Errorf("chained level %d style %s offers %s", p, style, n)
				}
			}
			if len(PsiphonProtocols(p, style, true)) == 0 {
				t.Errorf("chained level %d style %s has no protocols", p, style)
			}
		}
	}
	if PsiphonProtocols(2, "auto", false) != nil {
		t.Error("level 2 must not limit protocols")
	}
	for _, n := range PsiphonProtocols(1, "auto", false) {
		if strings.Contains(n, "CDN") {
			t.Errorf("level 1 must not name %s (stock tunnel-core rejects it)", n)
		}
	}
	for _, n := range PsiphonProtocols(0, "cdn", false) {
		if !strings.Contains(n, "CDN") {
			t.Errorf("cdn style offers %s", n)
		}
	}
}

func TestPsiphonConfigFile(t *testing.T) {
	c := testCfg(t)
	c.Psiphon.Region = "de"
	p := NewPsiphon(c)
	p.dir, p.cfgPath = c.DataDir, filepath.Join(c.DataDir, "client.config")
	p.port.Store(8811)
	p.Upstream = "socks5://127.0.0.1:8812"
	if err := p.writeConfig(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p.cfgPath)
	var conf map[string]any
	if err := json.Unmarshal(b, &conf); err != nil {
		t.Fatal(err)
	}
	if conf["LocalSocksProxyPort"] != float64(8811) || conf["UpstreamProxyURL"] != "socks5://127.0.0.1:8812" {
		t.Errorf("port / upstream: %v %v", conf["LocalSocksProxyPort"], conf["UpstreamProxyURL"])
	}
	if conf["EgressRegion"] != "DE" || conf["DisableTactics"] != true || conf["DisableLocalHTTPProxy"] != true {
		t.Errorf("region / tactics: %v", conf)
	}
	for _, n := range conf["LimitTunnelProtocols"].([]any) {
		if strings.Contains(n.(string), "QUIC") {
			t.Errorf("a chained config offers %v", n)
		}
	}
}

func TestPsiphonNoticesDriveReadiness(t *testing.T) {
	p := NewPsiphon(testCfg(t))
	p.handleLine(`{"noticeType":"Tunnels","data":{"count":1}}`)
	if !p.Ready() {
		t.Error("a tunnel notice did not make psiphon ready")
	}
	p.handleLine(`{"noticeType":"Tunnels","data":{"count":0}}`)
	if p.Ready() {
		t.Error("a zero-tunnel notice left psiphon ready")
	}
	p.handleLine(`{"noticeType":"Alert","data":{"message":"no servers"}}`)
	if p.LastError() != "no servers" {
		t.Errorf("error %q", p.LastError())
	}
	p.handleLine("plain text before exit")
	if len(p.tail) == 0 {
		t.Error("plain text was not remembered")
	}
}

func TestPsiphonEarlyExitFallsBackToASimplerProtocolList(t *testing.T) {
	c := testCfg(t)
	p := NewPsiphon(c)
	p.dir, p.cfgPath = c.DataDir, filepath.Join(c.DataDir, "client.config")
	p.port.Store(8811)
	p.t0 = time.Now()
	p.handleExit(procExit())
	if p.profile != 1 {
		t.Errorf("profile %d after the first early exit, want 1", p.profile)
	}
	p.t0 = time.Now()
	p.handleExit(procExit())
	if p.profile != 2 {
		t.Errorf("profile %d after the second early exit, want 2", p.profile)
	}
	p.t0 = time.Now()
	p.handleExit(procExit())
	if p.profile != 2 {
		t.Errorf("profile %d: it must stop at level 2", p.profile)
	}
	chained := NewPsiphon(c)
	chained.Upstream = "socks5://127.0.0.1:1"
	chained.dir, chained.cfgPath = c.DataDir, filepath.Join(c.DataDir, "chained.config")
	for i := 0; i < 3; i++ {
		chained.t0 = time.Now()
		chained.handleExit(procExit())
	}
	if chained.profile != 1 {
		t.Errorf("a chained psiphon went to level %d, the limit is 1", chained.profile)
	}
	late := NewPsiphon(c)
	late.t0 = time.Now().Add(-time.Minute)
	late.handleExit(procExit())
	if late.profile != 0 {
		t.Error("a late exit must not change the protocol list")
	}
}

// ---------- the not-ready contract ----------

func TestNotReadyBackendsReturnErrNotReady(t *testing.T) {
	c := testCfg(t)
	for name, b := range map[string]core.Backend{
		"warp":    NewWarp(c),
		"auto":    NewAutoWarp(c),
		"aether":  NewAetherWarp(c, "masque"),
		"psiphon": NewPsiphon(c),
		"tor":     NewTor(c),
	} {
		if b.Ready() {
			t.Errorf("%s: ready before Start", name)
		}
		if _, err := b.DialTCP(context.Background(), "example.com:80"); !errors.Is(err, core.ErrNotReady) {
			t.Errorf("%s TCP: %v, want ErrNotReady", name, err)
		}
	}
	for name, b := range map[string]core.Backend{"warp": NewWarp(c), "aether": NewAetherWarp(c, "gool")} {
		if _, err := b.DialUDP(context.Background(), "1.1.1.1:53"); !errors.Is(err, core.ErrNotReady) {
			t.Errorf("%s UDP: %v, want ErrNotReady", name, err)
		}
	}
}

func TestBackendsWithoutUDPSayNoUDP(t *testing.T) {
	c := testCfg(t)
	for name, b := range map[string]core.Backend{"psiphon": NewPsiphon(c), "tor": NewTor(c), "chain": NewChainTor(c, "wg")} {
		if b.SupportsUDP() {
			t.Errorf("%s claims UDP", name)
		}
		if _, err := b.DialUDP(context.Background(), "1.1.1.1:53"); !errors.Is(err, core.ErrUDPUnsupported) {
			t.Errorf("%s UDP: %v, want ErrUDPUnsupported", name, err)
		}
	}
}

func TestErrorTextsAreUnchanged(t *testing.T) {
	c := testCfg(t)
	ctx := context.Background()
	check := func(b core.Backend, want string) {
		_, err := b.DialTCP(ctx, "x:1")
		if err == nil || err.Error() != want {
			t.Errorf("%T: %v, want %q", b, err, want)
		}
	}
	check(NewWarp(c), "warp not connected")
	check(NewPsiphon(c), "psiphon not connected")
	check(NewTor(c), "tor not bootstrapped")
	check(NewAetherWarp(c, "mim"), "warp/mim is not connected")
	check(NewAutoWarp(c), "warp (auto) is still looking for a route that works")
}

func TestMissingProgramsGiveClearStartErrors(t *testing.T) {
	c := testCfg(t)
	if AetherBin(c) != "" || PsiphonBin(c) != "" || TorBin(c) != "" {
		t.Skip("a helper program is installed on this machine")
	}
	for name, b := range map[string]core.Backend{
		"aether": NewAetherWarp(c, "masque"), "psiphon": NewPsiphon(c), "tor": NewTor(c),
	} {
		err := b.Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("%s: %v", name, err)
		}
		if b.Ready() {
			t.Errorf("%s ready after a failed start", name)
		}
	}
}

// ---------- helper programs unpacked from the executable are found ----------

func TestUnpackedProgramsAreFound(t *testing.T) {
	c := testCfg(t)
	if AetherBin(c) != "" {
		t.Skip("aether is installed on this machine")
	}
	want := fakeProgram(t, c, "aether")
	got := AetherBin(c)
	abs, _ := filepath.Abs(want)
	if got != abs {
		t.Errorf("AetherBin = %q, want %q", got, abs)
	}
	fakeProgram(t, c, "psiphon-tunnel-core")
	if PsiphonBin(c) == "" {
		t.Error("psiphon not found in <data_dir>/bin")
	}
	fakeProgram(t, c, "tor")
	if TorBin(c) == "" {
		t.Error("tor not found in <data_dir>/bin")
	}
	// an explicit path from Settings wins over everything
	other := filepath.Join(t.TempDir(), "my-aether"+exe())
	os.WriteFile(other, []byte("x"), 0o755)
	c.Aether.Bin = other
	if AetherBin(c) != other {
		t.Errorf("explicit path ignored: %q", AetherBin(c))
	}
}

// ---------- variants and the auto waves ----------

func TestVariantAvailable(t *testing.T) {
	c := testCfg(t)
	if !VariantAvailable(c, "wg") || !VariantAvailable(c, "auto") {
		t.Error("the built-in WireGuard and auto must always be available")
	}
	if AetherBin(c) != "" {
		t.Skip("aether is installed on this machine")
	}
	for _, v := range []string{"masque", "masque-h2", "gool", "gool-classic", "mim", "wg-noize"} {
		if VariantAvailable(c, v) {
			t.Errorf("%s reported available without aether", v)
		}
	}
	fakeProgram(t, c, "aether")
	for _, v := range config.WarpVariants {
		if !VariantAvailable(c, v) {
			t.Errorf("%s unavailable although aether is present", v)
		}
	}
}

func TestAutoWavesWithoutAether(t *testing.T) {
	c := testCfg(t)
	if AetherBin(c) != "" {
		t.Skip("an aether program is installed here")
	}
	waves := NewAutoWarp(c).waves()
	if len(waves) == 0 {
		t.Fatal("no wave left: the built-in WireGuard must always be tried")
	}
	for _, w := range waves {
		for _, v := range w {
			if config.VariantNeedsAether(v) {
				t.Errorf("variant %s needs aether but aether is missing", v)
			}
		}
	}
	if len(waves) != 1 || waves[0][0] != "wg" {
		t.Errorf("without aether auto should try only wg, got %v", waves)
	}
}

func TestAutoTriesMasqueH2First(t *testing.T) {
	c := testCfg(t)
	if AetherBin(c) != "" {
		t.Skip("an aether program is installed here")
	}
	fakeProgram(t, c, "aether")
	waves := NewAutoWarp(c).waves()
	if len(waves) < 2 || len(waves[0]) != 1 || waves[0][0] != "masque-h2" {
		t.Fatalf("the first wave must be MASQUE HTTP/2 alone, got %v", waves)
	}
	seen := map[string]bool{}
	for _, w := range waves {
		for _, v := range w {
			seen[v] = true
		}
	}
	for _, v := range []string{"wg", "masque", "gool", "wg-noize", "mim", "gool-classic"} {
		if !seen[v] {
			t.Errorf("variant %s is never tried by auto", v)
		}
	}
}

func TestAutoWavesFromConfig(t *testing.T) {
	c := testCfg(t)
	c.Warp.Auto = []string{"wg", "bogus+wg", "auto"}
	waves := NewAutoWarp(c).waves()
	if len(waves) != 2 || waves[0][0] != "wg" || waves[1][0] != "wg" || len(waves[1]) != 1 {
		t.Errorf("waves %v: unknown names and \"auto\" must be dropped", waves)
	}
}

func TestNewWarpBackendPicksTheRightEngine(t *testing.T) {
	c := testCfg(t)
	if _, ok := NewWarpBackend(c, "wg").(*Warp); !ok {
		t.Error("wg is the built-in engine")
	}
	for _, v := range []string{"auto", ""} {
		if _, ok := NewWarpBackend(c, v).(*AutoWarp); !ok {
			t.Errorf("%q is the auto engine", v)
		}
	}
	for _, v := range []string{"masque", "masque-h2", "gool", "gool-classic", "mim", "wg-noize"} {
		a, ok := NewWarpBackend(c, v).(*AetherWarp)
		if !ok || a.Variant() != v {
			t.Errorf("%s: %T", v, NewWarpBackend(c, v))
		}
	}
}

func TestAetherArguments(t *testing.T) {
	c := testCfg(t)
	has := func(args []string, want ...string) bool {
		for i := range args {
			if i+len(want) > len(args) {
				return false
			}
			ok := true
			for j := range want {
				if args[i+j] != want[j] {
					ok = false
				}
			}
			if ok {
				return true
			}
		}
		return false
	}
	cases := map[string][][]string{
		"masque":       {{"--masque", "--h3"}},
		"masque-h2":    {{"--masque", "--h2"}},
		"gool":         {{"--gool"}},
		"gool-classic": {{"--gool-classic"}},
		"mim":          {{"--mim"}},
		"wg-noize":     {{"--wg"}, {"--noize", "gfw"}},
	}
	for v, wants := range cases {
		a := NewAetherWarp(c, v)
		a.port.Store(8811)
		args := a.args()
		for _, want := range wants {
			if !has(args, want...) {
				t.Errorf("%s: %v lacks %v", v, args, want)
			}
		}
		if !has(args, "--bind", "127.0.0.1:8811") || !has(args, "--quick-reconnect") || !has(args, "--fragment") || !has(args, "-4") {
			t.Errorf("%s: common flags missing in %v", v, args)
		}
		if !has(args, "--scan", "balanced") || !has(args, "--log-level", "info") {
			t.Errorf("%s: scan / log level missing in %v", v, args)
		}
	}
	c.Aether.IP, c.Aether.Noize, c.Aether.Fragment, c.Verbose = "both", "light", false, true
	a := NewAetherWarp(c, "masque")
	a.port.Store(1)
	args := a.args()
	if !has(args, "--dual") || !has(args, "--noize", "light") || has(args, "--fragment") || !has(args, "--log-level", "debug") {
		t.Errorf("options not applied: %v", args)
	}
	c.Aether.IP = "6"
	if !has(NewAetherWarp(c, "mim").args(), "-6") {
		t.Error("IPv6 flag missing")
	}
}

// ---------- WARP built-in: files, identity, endpoints ----------

func TestParseWGConf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wgcf.conf")
	os.WriteFile(p, []byte("[Interface]\nPrivateKey = abc=\nAddress = 172.16.0.2/32, 2606:4700::2/128\n[Peer]\nPublicKey = def=\nEndpoint = engage.cloudflareclient.com:2408\n"), 0o600)
	id, err := parseWGConf(p)
	if err != nil {
		t.Fatal(err)
	}
	if id.PrivateKey != "abc=" || id.PeerPublic != "def=" || id.V4 != "172.16.0.2/32" || id.V6 != "2606:4700::2/128" {
		t.Errorf("parsed %+v", id)
	}
	os.WriteFile(p, []byte("[Interface]\nPrivateKey = abc=\n"), 0o600)
	if _, err := parseWGConf(p); err == nil {
		t.Error("an incomplete profile was accepted")
	}
	if _, err := parseWGConf(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing profile was accepted")
	}
}

func TestReadAetherIdentity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "aether.toml")
	os.WriteFile(p, []byte("wg_private_key = \"priv=\"\nwg_peer_public_key = 'pub='\nipv4 = \"172.16.0.2/32\"\nipv6 = \"2606::2/128\"\nother = 1\n"), 0o600)
	id, err := readAetherIdentity(p)
	if err != nil || id.PrivateKey != "priv=" || id.PeerPublic != "pub=" || id.V4 != "172.16.0.2/32" || id.V6 != "2606::2/128" {
		t.Errorf("identity %+v err %v", id, err)
	}
	os.WriteFile(p, []byte("ipv4 = \"1.2.3.4/32\"\n"), 0o600)
	if _, err := readAetherIdentity(p); err == nil {
		t.Error("an incomplete identity was accepted")
	}
}

func TestIdentityFileFormatIsStable(t *testing.T) {
	// warp-identity.json written by v1.0 must still load
	raw := `{"private_key":"cHJpdg==","peer_public_key":"cHVi","v4":"172.16.0.2/32","v6":"2606::2/128"}`
	var id warpIdentity
	if err := json.Unmarshal([]byte(raw), &id); err != nil || id.PrivateKey != "cHJpdg==" || id.V4 != "172.16.0.2/32" {
		t.Fatalf("%+v %v", id, err)
	}
	c := testCfg(t)
	os.WriteFile(filepath.Join(c.DataDir, "warp-identity.json"), []byte(raw), 0o600)
	got, err := NewWarp(c).identity(context.Background())
	if err != nil || got.PeerPublic != "cHVi" {
		t.Errorf("identity() = %+v, %v", got, err)
	}
}

func TestResetWarpIdentity(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "warp-identity.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(d, "warp-endpoint.txt"), []byte("1.2.3.4:2408"), 0o600)
	ResetWarpIdentity(d)
	for _, f := range []string{"warp-identity.json", "warp-endpoint.txt"} {
		if _, err := os.Stat(filepath.Join(d, f)); err == nil {
			t.Errorf("%s still there", f)
		}
	}
}

func TestEndpointCandidates(t *testing.T) {
	c := testCfg(t)
	os.WriteFile(filepath.Join(c.DataDir, "warp-endpoint.txt"), []byte("9.9.9.9:2408\n"), 0o600)
	c.Warp.Endpoints = []string{"5.6.7.8:500", "9.9.9.9:2408"}
	got := NewWarp(c).candidates()
	if len(got) < 3 || got[0] != "9.9.9.9:2408" || got[1] != "5.6.7.8:500" {
		t.Fatalf("order: %v (last good endpoint first, then the configured ones)", got[:3])
	}
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e] {
			t.Errorf("duplicate candidate %s", e)
		}
		seen[e] = true
	}
	if !seen["162.159.192.1:2408"] || !seen["188.114.99.1:854"] {
		t.Error("the built-in fallback endpoints are missing")
	}
}

type recConn struct {
	net.Conn
	writes [][]byte
}

func (r *recConn) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestFragConnSplitsOnlyTheFirstWrite(t *testing.T) {
	r := &recConn{}
	f := &fragConn{Conn: r}
	hello := make([]byte, 300)
	for i := range hello {
		hello[i] = byte(i)
	}
	f.Write(hello)
	if len(r.writes) < 300/16 {
		t.Fatalf("the ClientHello went out in %d pieces", len(r.writes))
	}
	var joined []byte
	for _, w := range r.writes {
		if len(w) < 1 || len(w) > 16 {
			t.Errorf("piece of %d bytes", len(w))
		}
		joined = append(joined, w...)
	}
	if string(joined) != string(hello) {
		t.Error("the pieces do not add up to the original")
	}
	n := len(r.writes)
	f.Write([]byte("second write, sent whole"))
	if len(r.writes) != n+1 {
		t.Error("only the first write may be split")
	}
}

// ---------- supervised helper programs, end to end (POSIX shell needed) ----------

func TestTorStartsStopsAndReportsBootstrap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	c := testCfg(t)
	c.Tor.Bridge = "none"
	p := filepath.Join(c.DataDir, "fake-tor")
	os.WriteFile(p, []byte("#!/bin/sh\necho 'Nov 01 12:00:00.000 [notice] Bootstrapped 50% (loading_descriptors)'\necho 'Nov 01 12:00:01.000 [notice] Bootstrapped 100% (done): Done'\nsleep 60\n"), 0o755)
	c.Tor.Bin = p
	tor := NewTor(c)
	if err := tor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !tor.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("tor never became ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	port := tor.port.Load()
	rc, _ := os.ReadFile(filepath.Join(c.DataDir, "tor", "torrc"))
	if !strings.Contains(string(rc), "SocksPort 127.0.0.1:") || strings.Contains(string(rc), "UseBridges") {
		t.Errorf("torrc:\n%s", rc)
	}
	t0 := time.Now()
	tor.Stop()
	if tor.Ready() {
		t.Error("ready after Stop")
	}
	if time.Since(t0) > 6*time.Second {
		t.Errorf("Stop took %s", time.Since(t0))
	}
	if tor.port.Load() != 0 || port == 0 {
		t.Errorf("port bookkeeping: before %d after %d", port, tor.port.Load())
	}
}

func TestTorChainedUsesTheUpstreamProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	c := testCfg(t)
	c.Tor.Bridge = "none"
	p := filepath.Join(c.DataDir, "fake-tor")
	os.WriteFile(p, []byte("#!/bin/sh\nsleep 60\n"), 0o755)
	c.Tor.Bin = p
	tor := NewTor(c)
	tor.Upstream = "127.0.0.1:8855"
	if err := tor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer tor.Stop()
	rc, _ := os.ReadFile(filepath.Join(c.DataDir, "tor", "torrc"))
	if !strings.Contains(string(rc), "Socks5Proxy 127.0.0.1:8855") {
		t.Errorf("torrc lacks the upstream proxy:\n%s", rc)
	}
}

func TestTorWithoutUsableBridgesFailsClearly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	c := testCfg(t)
	p := filepath.Join(c.DataDir, "fake-tor")
	os.WriteFile(p, []byte("#!/bin/sh\nsleep 60\n"), 0o755)
	c.Tor.Bin = p
	c.Tor.Bridge = "obfs4"
	if PluggableTransportsInstalled(c) {
		t.Skip("a pluggable transport is installed on this machine")
	}
	err := NewTor(c).Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no usable") {
		t.Errorf("got %v", err)
	}
}

func TestChainStartsInnerEngineOnlyAfterWarpIsUp(t *testing.T) {
	c := testCfg(t)
	w := &stubWarp{}
	in := &stubInner{}
	chain := &Chain{name: "warp+tor", w: w, inner: in, setUp: func(string) {}}
	if err := chain.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer chain.Stop()
	time.Sleep(700 * time.Millisecond)
	if in.started.Load() {
		t.Fatal("the inner engine started before WARP was up")
	}
	if got := chain.LastError(); !strings.Contains(got, "waiting for WARP") {
		t.Errorf("LastError while waiting: %q", got)
	}
	w.ready.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for !in.started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the inner engine never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = c
}

func TestChainReportsInnerStartError(t *testing.T) {
	w := &stubWarp{}
	w.ready.Store(true)
	in := &stubInner{startErr: errors.New("tor binary not found")}
	chain := &Chain{name: "warp+tor", w: w, inner: in, setUp: func(string) {}}
	chain.Start(context.Background())
	defer chain.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for chain.LastError() != "tor binary not found" {
		if time.Now().After(deadline) {
			t.Fatalf("LastError = %q", chain.LastError())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestChainStopStopsBothEngines(t *testing.T) {
	w, in := &stubWarp{}, &stubInner{}
	chain := &Chain{name: "warp+psiphon", w: w, inner: in, setUp: func(string) {}}
	chain.Start(context.Background())
	chain.Stop()
	if !w.stopped.Load() || !in.stopped.Load() {
		t.Errorf("stopped: warp %v inner %v", w.stopped.Load(), in.stopped.Load())
	}
	chain.Stop() // twice is harmless
}
