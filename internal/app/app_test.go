package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"clubconnect/internal/backends"
	"clubconnect/internal/config"
	"clubconnect/internal/core"
	"clubconnect/internal/logx"
)

func TestMain(m *testing.M) {
	logx.InitWriter(io.Discard, slog.LevelError)
	os.Exit(m.Run())
}

func freeTCPPort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// quietCfg is a configuration that starts nothing that needs a network: the auto mode only has
// tor, whose program is missing, so the manager just reports it as disabled.
func quietCfg(t *testing.T) *config.Config {
	c := config.Default()
	c.DataDir = t.TempDir()
	c.Port = freeTCPPort(t)
	c.Order = []string{"tor"}
	c.Tor.Bin, c.Psiphon.Bin, c.Aether.Bin = "", "", ""
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func newCtl(t *testing.T, c *config.Config) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctl := NewController(ctx, c, Info{Name: "Club Connect", Version: "0.8-test"})
	t.Cleanup(ctl.Stop)
	return ctl
}

func TestBackendsForEveryMode(t *testing.T) {
	c := quietCfg(t)
	c.Order = []string{"warp", "psiphon", "tor"}
	names := func(bs []core.Backend) string {
		var n []string
		for _, b := range bs {
			n = append(n, b.Name())
		}
		return strings.Join(n, ",")
	}
	cases := map[string]struct{ names, pin string }{
		"auto":         {"warp,psiphon,tor", ""},
		"warp":         {"warp", "warp"},
		"psiphon":      {"psiphon", "psiphon"},
		"tor":          {"tor", "tor"},
		"warp+psiphon": {"warp+psiphon", "warp+psiphon"},
		"warp+tor":     {"warp+tor", "warp+tor"},
	}
	for mode, want := range cases {
		bs, pin, err := BackendsFor(c, mode, "wg")
		if err != nil || names(bs) != want.names || pin != want.pin {
			t.Errorf("%s: %q pin %q err %v, want %q pin %q", mode, names(bs), pin, err, want.names, want.pin)
		}
	}
	// every mode's variant is passed on
	bs, _, _ := BackendsFor(c, "warp", "gool")
	if core.VariantOf(bs[0]) != "gool" {
		t.Errorf("variant lost: %q", core.VariantOf(bs[0]))
	}
	bs, _, _ = BackendsFor(c, "warp+tor", "masque-h2")
	if core.VariantOf(bs[0]) != "masque-h2" {
		t.Errorf("chain variant lost: %q", core.VariantOf(bs[0]))
	}
}

func TestBackendsForErrors(t *testing.T) {
	c := quietCfg(t)
	if _, _, err := BackendsFor(c, "teleport", ""); !errors.Is(err, ErrUnknownMode) {
		t.Errorf("unknown mode: %v", err)
	}
	c.Order = []string{"warp", "carrier-pigeon"}
	if _, _, err := BackendsFor(c, "auto", ""); err == nil || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Errorf("unknown backend in order: %v", err)
	}
	c.Order = nil
	if _, _, err := BackendsFor(c, "auto", ""); !errors.Is(err, ErrNoBackends) {
		t.Errorf("empty order: %v", err)
	}
}

func TestStartStopLifecycle(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	if running, _ := ctl.Running(); running {
		t.Fatal("running before Start")
	}
	if st := ctl.Status(); st.Running || st.Version != "0.8-test" || st.Port != c.Port || st.Backends == nil {
		t.Errorf("idle status %+v", st)
	}
	if err := ctl.Start("auto"); err != nil {
		t.Fatal(err)
	}
	if running, mode := ctl.Running(); !running || mode != "auto" {
		t.Errorf("Running() = %v %q", running, mode)
	}
	st := ctl.Status()
	if !st.Running || st.RunMode != "auto" || st.LastMode != "auto" || st.Port != c.Port || len(st.Backends) != 1 {
		t.Errorf("running status %+v", st)
	}
	// the proxy port is really open
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)), 2*time.Second)
	if err != nil {
		t.Fatalf("the proxy is not listening: %v", err)
	}
	conn.Close()

	// stopping frees the port
	ctl.Stop()
	if running, _ := ctl.Running(); running {
		t.Error("still running after Stop")
	}
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)))
	if err != nil {
		t.Fatalf("the port is still taken after Stop: %v", err)
	}
	l.Close()
	ctl.Stop() // twice is harmless

	// and the mode was remembered for next time
	b, err := os.ReadFile(filepath.Join(c.DataDir, "settings.json"))
	if err != nil || !strings.Contains(string(b), `"last_mode": "auto"`) {
		t.Errorf("settings.json: %s %v", b, err)
	}
}

func TestStartingAgainReplacesTheRunningMode(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	if err := ctl.Start("auto"); err != nil {
		t.Fatal(err)
	}
	if err := ctl.Start("auto"); err != nil {
		t.Fatalf("restart on the same port: %v", err)
	}
	if running, _ := ctl.Running(); !running {
		t.Error("not running after the restart")
	}
}

func TestStartErrors(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	if err := ctl.Start("teleport"); !errors.Is(err, ErrUnknownMode) || !strings.Contains(err.Error(), "use one of: auto, warp") {
		t.Errorf("unknown mode: %v", err)
	}
	if err := ctl.Start("warp@nonsense"); !errors.Is(err, ErrUnknownVariant) {
		t.Errorf("unknown variant: %v", err)
	}
	if backends.PsiphonBin(c) == "" {
		if err := ctl.Start("psiphon"); !errors.Is(err, ErrMissingProgram) {
			t.Errorf("missing psiphon: %v", err)
		}
	}
	if backends.TorBin(c) == "" {
		if err := ctl.Start("warp+tor"); !errors.Is(err, ErrMissingProgram) {
			t.Errorf("missing tor: %v", err)
		}
	}
	if backends.AetherBin(c) == "" {
		err := ctl.Start("warp@masque-h2")
		if !errors.Is(err, ErrMissingProgram) || !strings.Contains(err.Error(), "masque-h2") {
			t.Errorf("missing aether: %v", err)
		}
	}
	if running, _ := ctl.Running(); running {
		t.Error("a refused start left something running")
	}
	// a busy port is reported, and the old mode is gone (Start stops it first)
	busy, _ := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)))
	defer busy.Close()
	if err := ctl.Start("auto"); !errors.Is(err, ErrPortInUse) {
		t.Errorf("busy port: %v", err)
	}
}

func TestVariantOfTheFirstStartCanComeFromTheCommandLine(t *testing.T) {
	c := quietCfg(t)
	c.ModeVariant = "auto"     // -variant auto
	c.SetVariant("auto", "wg") // what the menu had chosen for the auto mode
	ctl := newCtl(t, c)
	if err := ctl.Start("auto"); err != nil {
		t.Fatal(err)
	}
	if v := ctl.Status().Variant; v != "auto" {
		t.Errorf("first start used variant %q, want the command line's auto", v)
	}
	if c.ModeVariant != "" {
		t.Error("ModeVariant must be used for one start only")
	}
	if err := ctl.Start("auto"); err != nil {
		t.Fatal(err)
	}
	if v := ctl.Status().Variant; v != "wg" {
		t.Errorf("the second start used %q, want the stored variant (wg)", v)
	}
	// an explicit variant in the mode spec beats both
	if err := ctl.Start("auto@auto"); err != nil {
		t.Fatal(err)
	}
	if v := ctl.Status().Variant; v != "auto" {
		t.Errorf("auto@auto used %q", v)
	}
}

func TestSwitch(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	if err := ctl.Switch("tor"); !errors.Is(err, ErrNotRunning) || err.Error() != "not running - start a mode first" {
		t.Errorf("not running: %v", err)
	}
	ctl.Start("auto")
	if err := ctl.Switch("warp"); !errors.Is(err, core.ErrUnknownBackend) {
		t.Errorf("a backend the mode does not have: %v", err)
	}
	if err := ctl.Switch("tor"); err != nil {
		t.Errorf("switch to tor: %v", err)
	}
	if err := ctl.Switch("auto"); err != nil {
		t.Errorf("switch back to auto: %v", err)
	}
}

func TestTestWhenNotRunning(t *testing.T) {
	ctl := newCtl(t, quietCfg(t))
	if got := ctl.Test(); got != "not running - start a mode first" {
		t.Errorf("Test() = %q", got)
	}
}

func TestStatusJSONShapeIsStable(t *testing.T) {
	ctl := newCtl(t, quietCfg(t))
	ctl.Start("auto")
	b, _ := json.Marshal(ctl.Status())
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"version", "running", "run_mode", "variant", "last_mode", "port", "mode", "active", "bytes_up", "bytes_down", "backends"} {
		if _, ok := m[k]; !ok {
			t.Errorf("the status lost its %q field: %s", k, b)
		}
	}
	bk := m["backends"].([]any)[0].(map[string]any)
	for _, k := range []string{"name", "ready", "healthy", "latency_ms", "udp"} {
		if _, ok := bk[k]; !ok {
			t.Errorf("a backend status lost its %q field: %s", k, b)
		}
	}
}

func TestVariantsListing(t *testing.T) {
	c := quietCfg(t)
	vs := newCtl(t, c).Variants()
	if len(vs) != len(config.WarpVariants) {
		t.Fatalf("%d variants, want %d", len(vs), len(config.WarpVariants))
	}
	for i, v := range vs {
		if v.Name != config.WarpVariants[i] || v.Label == "" {
			t.Errorf("entry %d: %+v", i, v)
		}
		if v.Available != backends.VariantAvailable(c, v.Name) {
			t.Errorf("%s availability disagrees with VariantAvailable", v.Name)
		}
	}
}

func TestIsTerminalOnAPipeIsFalse(t *testing.T) {
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	if IsTerminal(r) {
		t.Error("a pipe is not a terminal")
	}
}

// 0 closes the menu only: before v0.8 it stopped the whole core.
func TestZeroClosesTheMenuButKeepsTheCoreRunning(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() { RunMenuFrom(ctx, ctl, c, pr); close(done) }()
	waitRunning := func(want bool) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if r, _ := ctl.Running(); r == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("Running() never became %v", want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	io.WriteString(pw, "1\n\n") // Auto, then Enter to keep the WARP variant
	waitRunning(true)
	io.WriteString(pw, "0\n")
	select {
	case <-done:
		t.Fatal("the menu exited on 0 while a mode was running")
	case <-time.After(300 * time.Millisecond):
	}
	if r, _ := ctl.Running(); !r {
		t.Fatal("0 stopped the running mode")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.Port)), 2*time.Second)
	if err != nil {
		t.Fatalf("the proxy stopped listening after 0: %v", err)
	}
	conn.Close()
	io.WriteString(pw, "\n") // Enter: the menu is back
	io.WriteString(pw, "s\n")
	waitRunning(false) // the menu works again, S stops
	io.WriteString(pw, "1\n\n")
	waitRunning(true)
	io.WriteString(pw, "q\n") // Q stops everything and leaves
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Q did not leave the menu")
	}
	if r, _ := ctl.Running(); r {
		t.Error("Q left the mode running")
	}
}

func TestZeroWithNothingRunningLeavesAtOnce(t *testing.T) {
	c := quietCfg(t)
	ctl := newCtl(t, c)
	done := make(chan struct{})
	go func() { RunMenuFrom(context.Background(), ctl, c, strings.NewReader("0\n")); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the menu stayed open")
	}
}
