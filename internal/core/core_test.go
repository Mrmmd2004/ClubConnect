package core

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"clubconnect/internal/logx"
)

func TestMain(m *testing.M) {
	logx.InitWriter(io.Discard, slog.LevelError) // keep the test output quiet
	os.Exit(m.Run())
}

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestPick(t *testing.T) {
	h := func(lat int) Candidate { return Candidate{true, ms(lat)} }
	down := Candidate{}
	cases := []struct {
		name   string
		cs     []Candidate
		cur    int
		want   int
		wantOK bool
	}{
		{"nobody healthy keeps the current one", []Candidate{down, down}, 1, 1, false},
		{"nobody healthy, nothing active yet", []Candidate{down, down}, -1, -1, false},
		{"first healthy backend becomes active", []Candidate{down, h(80), down}, -1, 1, true},
		{"fastest wins when nothing is active", []Candidate{h(90), h(40), h(60)}, -1, 1, true},
		{"a tie goes to the earlier backend", []Candidate{h(50), h(50)}, -1, 0, true},
		{"current stays while within 1.4x of the best", []Candidate{h(95), h(70)}, 0, 0, true},
		{"exactly 1.4x still stays", []Candidate{h(140), h(100)}, 0, 0, true},
		{"just beyond 1.4x switches", []Candidate{h(141), h(100)}, 0, 1, true},
		{"unhealthy current is left at once", []Candidate{down, h(500)}, 0, 1, true},
		{"current already best", []Candidate{h(10), h(20)}, 0, 0, true},
		{"current index out of range", []Candidate{h(10)}, 7, 0, true},
		{"no backends at all", nil, -1, -1, false},
	}
	for _, c := range cases {
		got, ok := Pick(c.cs, c.cur)
		if got != c.want || ok != c.wantOK {
			t.Errorf("%s: Pick = (%d,%v), want (%d,%v)", c.name, got, ok, c.want, c.wantOK)
		}
	}
}

// Two engines of similar speed whose latencies jitter must not trade places every round.
func TestPickDoesNotFlap(t *testing.T) {
	cur := -1
	switches := 0
	lats := [][2]int{{100, 90}, {95, 105}, {110, 80}, {90, 100}, {120, 100}, {100, 120}}
	for _, l := range lats {
		next, ok := Pick([]Candidate{{true, ms(l[0])}, {true, ms(l[1])}}, cur)
		if ok && next != cur {
			switches++
			cur = next
		}
	}
	if switches > 1 {
		t.Errorf("active backend changed %d times on jitter alone", switches)
	}
}

type fake struct {
	Base
	name     string
	udp      bool
	dialErr  error
	tcpDials atomic.Int32
	udpDials atomic.Int32
	started  atomic.Bool
	stopped  atomic.Bool
	startErr error
	variant  string
}

func (f *fake) Name() string      { return f.name }
func (f *fake) SupportsUDP() bool { return f.udp }
func (f *fake) Variant() string   { return f.variant }
func (f *fake) Start(ctx context.Context) error {
	f.started.Store(true)
	if f.startErr != nil {
		return f.startErr
	}
	f.SetReady(true)
	return nil
}
func (f *fake) Stop() { f.stopped.Store(true); f.SetReady(false) }
func (f *fake) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	f.tcpDials.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	a, b := net.Pipe()
	go func() { io.Copy(b, b); b.Close() }() // echo
	return a, nil
}
func (f *fake) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	f.udpDials.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	a, _ := net.Pipe()
	return a, nil
}

func ready(name string, udp bool) *fake {
	f := &fake{name: name, udp: udp}
	f.SetReady(true)
	return f
}

func TestDialFailsOverToTheNextBackend(t *testing.T) {
	bad := ready("warp", true)
	bad.dialErr = errors.New("boom")
	good := ready("tor", false)
	m := NewManager(Options{}, []Backend{bad, good})
	m.active.Store(0)
	c, err := m.DialTCP(context.Background(), "example.com:80")
	if err != nil {
		t.Fatalf("expected failover, got %v", err)
	}
	c.Close()
	if bad.tcpDials.Load() != 1 || good.tcpDials.Load() != 1 {
		t.Errorf("dials: bad %d good %d", bad.tcpDials.Load(), good.tcpDials.Load())
	}
}

func TestDialTCPReportsLastError(t *testing.T) {
	a, b := ready("a", false), ready("b", false)
	a.dialErr, b.dialErr = errors.New("first"), errors.New("second")
	m := NewManager(Options{}, []Backend{a, b})
	if _, err := m.DialTCP(context.Background(), "x:1"); err == nil || err.Error() != "second" {
		t.Errorf("err = %v, want the last backend's error", err)
	}
}

func TestNoBackendReady(t *testing.T) {
	f := &fake{name: "warp"} // not ready
	m := NewManager(Options{}, []Backend{f})
	_, err := m.DialTCP(context.Background(), "x:1")
	if !errors.Is(err, ErrNoBackend) {
		t.Errorf("TCP: %v, want ErrNoBackend", err)
	}
	if err.Error() != "no backend is ready yet" {
		t.Errorf("message changed: %q", err)
	}
	_, err = m.DialUDP(context.Background(), "x:1")
	if !errors.Is(err, ErrNoUDPBackend) || err.Error() != "no UDP-capable backend is ready" {
		t.Errorf("UDP: %v", err)
	}
	if f.tcpDials.Load() != 0 {
		t.Error("a backend that is not ready was dialled")
	}
}

func TestUDPOnlyUsesUDPBackends(t *testing.T) {
	tcpOnly, withUDP := ready("psiphon", false), ready("warp", true)
	m := NewManager(Options{}, []Backend{tcpOnly, withUDP})
	m.active.Store(0)
	c, err := m.DialUDP(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if tcpOnly.udpDials.Load() != 0 || withUDP.udpDials.Load() != 1 {
		t.Errorf("udp dials: tcp-only %d, udp %d", tcpOnly.udpDials.Load(), withUDP.udpDials.Load())
	}
}

func TestActiveBackendIsTriedFirst(t *testing.T) {
	a, b := ready("a", false), ready("b", false)
	m := NewManager(Options{}, []Backend{a, b})
	m.active.Store(1)
	c, err := m.DialTCP(context.Background(), "x:1")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if a.tcpDials.Load() != 0 || b.tcpDials.Load() != 1 {
		t.Errorf("a %d b %d: the active backend (b) must be tried first", a.tcpDials.Load(), b.tcpDials.Load())
	}
}

func TestPinnedBackendWins(t *testing.T) {
	a, b := ready("a", false), ready("b", false)
	m := NewManager(Options{Pin: "b"}, []Backend{a, b})
	m.active.Store(0)
	c, err := m.DialTCP(context.Background(), "x:1")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if b.tcpDials.Load() != 1 || a.tcpDials.Load() != 0 {
		t.Errorf("pin ignored: a %d b %d", a.tcpDials.Load(), b.tcpDials.Load())
	}
	m.pick()
	if m.Status().Active != "b" {
		t.Errorf("pick moved away from the pin: %q", m.Status().Active)
	}
}

func TestSetMode(t *testing.T) {
	a, b := ready("a", false), ready("b", false)
	m := NewManager(Options{}, []Backend{a, b})
	if err := m.SetMode("nope"); !errors.Is(err, ErrUnknownBackend) || err.Error() != "unknown backend" {
		t.Errorf("unknown backend: %v", err)
	}
	if err := m.SetMode("b"); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Mode != "b" || st.Active != "b" {
		t.Errorf("after pin: mode %q active %q", st.Mode, st.Active)
	}
	if err := m.SetMode("auto"); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Mode != "auto" {
		t.Errorf("after unpin: mode %q", st.Mode)
	}
}

func TestThreeFailuresMarkUnhealthyAndKick(t *testing.T) {
	f := ready("warp", false)
	f.dialErr = errors.New("down")
	m := NewManager(Options{}, []Backend{f})
	m.bs[0].healthy = true
	for i := 0; i < 2; i++ {
		m.DialTCP(context.Background(), "x:1")
	}
	if h, _ := m.bs[0].snapshot(); !h {
		t.Fatal("marked unhealthy after only two failures")
	}
	m.DialTCP(context.Background(), "x:1")
	if h, _ := m.bs[0].snapshot(); h {
		t.Error("still healthy after three failures")
	}
	select {
	case <-m.kick:
	default:
		t.Error("the health loop was not woken")
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	f := ready("warp", false)
	m := NewManager(Options{}, []Backend{f})
	m.bs[0].healthy = true
	f.dialErr = errors.New("x")
	m.DialTCP(context.Background(), "x:1")
	m.DialTCP(context.Background(), "x:1")
	f.dialErr = nil
	c, _ := m.DialTCP(context.Background(), "x:1")
	c.Close()
	f.dialErr = errors.New("x")
	m.DialTCP(context.Background(), "x:1")
	m.DialTCP(context.Background(), "x:1")
	if h, _ := m.bs[0].snapshot(); !h {
		t.Error("failures that were not in a row marked it unhealthy")
	}
}

func TestByteCounters(t *testing.T) {
	m := NewManager(Options{}, []Backend{ready("a", false)})
	c, err := m.DialTCP(context.Background(), "x:1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("12345"))
	buf := make([]byte, 5)
	io.ReadFull(c, buf)
	if st := m.Status(); st.Up != 5 || st.Down != 5 {
		t.Errorf("up %d down %d, want 5 and 5", st.Up, st.Down)
	}
}

func TestStatus(t *testing.T) {
	f := ready("warp", true)
	f.variant = "masque"
	f.SetError("last problem")
	m := NewManager(Options{}, []Backend{f, &fake{name: "tor"}})
	st := m.Status()
	if len(st.Backends) != 2 || st.Mode != "auto" || st.Active != "" {
		t.Fatalf("status %+v", st)
	}
	b := st.Backends[0]
	if b.Name != "warp" || !b.Ready || !b.UDP || b.Variant != "masque" || b.Error != "last problem" {
		t.Errorf("backend status %+v", b)
	}
}

type checked struct {
	fake
	lat time.Duration
	ok  bool
}

func (c *checked) Health(context.Context) (time.Duration, bool) { return c.lat, c.ok }

func TestRunUsesHealthCheckerPicksFastestAndStopsOnCancel(t *testing.T) {
	slow := &checked{fake: fake{name: "tor"}, lat: ms(300), ok: true}
	fast := &checked{fake: fake{name: "warp"}, lat: ms(20), ok: true}
	broken := &checked{fake: fake{name: "psiphon"}, ok: false}
	m := NewManager(Options{FirstProbe: 10 * time.Millisecond, HealthInterval: time.Hour},
		[]Backend{slow, fast, broken})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Active != "warp" {
		if time.Now().After(deadline) {
			t.Fatalf("active never became warp: %+v", m.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := m.Status()
	if st.Backends[2].Healthy || !st.Backends[0].Healthy || st.Backends[1].LatencyMS != 20 {
		t.Errorf("health picture %+v", st.Backends)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	for _, b := range []*fake{&slow.fake, &fast.fake, &broken.fake} {
		if !b.stopped.Load() {
			t.Errorf("%s was not stopped", b.name)
		}
	}
}

func TestRunKeepsGoingWhenABackendCannotStart(t *testing.T) {
	bad := &fake{name: "tor", startErr: errors.New("tor binary not found")}
	good := &checked{fake: fake{name: "warp"}, lat: ms(5), ok: true}
	m := NewManager(Options{FirstProbe: 10 * time.Millisecond, HealthInterval: time.Hour}, []Backend{bad, good})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for m.Status().Active != "warp" {
		if time.Now().After(deadline) {
			t.Fatal("the working backend never became active")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestVariantOf(t *testing.T) {
	f := &fake{name: "warp", variant: "gool"}
	if VariantOf(f) != "gool" {
		t.Error("variant not reported")
	}
	if VariantOf(&plain{}) != "" {
		t.Error("a backend without Variant must report \"\"")
	}
}

// plain is a Backend that has no Variant method.
type plain struct{ Base }

func (*plain) Name() string                                      { return "plain" }
func (*plain) Start(context.Context) error                       { return nil }
func (*plain) Stop()                                             {}
func (*plain) SupportsUDP() bool                                 { return false }
func (*plain) DialTCP(context.Context, string) (net.Conn, error) { return nil, ErrNotReady }
func (*plain) DialUDP(context.Context, string) (net.Conn, error) { return nil, ErrNotReady }

func TestErrors(t *testing.T) {
	e := NotReady("psiphon not connected")
	if !errors.Is(e, ErrNotReady) || e.Error() != "psiphon not connected" {
		t.Errorf("NotReady: %v", e)
	}
	u := NoUDP("tor has no UDP")
	if !errors.Is(u, ErrUDPUnsupported) || errors.Is(u, ErrNotReady) || u.Error() != "tor has no UDP" {
		t.Errorf("NoUDP: %v", u)
	}
}

func TestBaseLifecycle(t *testing.T) {
	var b Base
	if b.Ready() || b.LastError() != "" {
		t.Fatal("a new Base must be idle")
	}
	b.SetError("oops")
	if b.LastError() != "oops" {
		t.Error("error not stored")
	}
	b.SetError("")
	if b.LastError() != "" {
		t.Error("error not cleared")
	}
	ctx := b.Begin(context.Background())
	var finished atomic.Bool
	b.Spawn(func() { <-ctx.Done(); time.Sleep(50 * time.Millisecond); finished.Store(true) })
	b.SetReady(true)
	b.End(5 * time.Second)
	if b.Ready() {
		t.Error("End must clear ready")
	}
	if !finished.Load() {
		t.Error("End did not wait for the spawned goroutine")
	}
	if ctx.Err() == nil {
		t.Error("End did not cancel the context")
	}
	b.End(time.Second) // a second End is harmless
}

func TestBaseEndGivesUpWaiting(t *testing.T) {
	var b Base
	b.Begin(context.Background())
	release := make(chan struct{})
	b.Spawn(func() { <-release })
	t0 := time.Now()
	b.End(100 * time.Millisecond)
	if d := time.Since(t0); d > 2*time.Second {
		t.Errorf("End waited %s although its limit was 100ms", d)
	}
	close(release)
}

func TestBaseGoIsNotWaitedFor(t *testing.T) {
	var b Base
	b.Begin(context.Background())
	release := make(chan struct{})
	b.Go(func() { <-release })
	t0 := time.Now()
	b.End(5 * time.Second)
	if time.Since(t0) > time.Second {
		t.Error("End waited for a Go goroutine")
	}
	close(release)
}

func TestBeginCancelsThePreviousRun(t *testing.T) {
	var b Base
	first := b.Begin(context.Background())
	b.Begin(context.Background())
	if first.Err() == nil {
		t.Error("the earlier run was left running")
	}
	b.End(0)
}
