package proc

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestHelperProcess is not a test: it is the program the tests below launch (the test binary
// itself), steered by environment variables.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("CC_HELPER") {
	case "":
		return
	case "lines":
		fmt.Println("out1")
		fmt.Fprintln(os.Stderr, "err1")
		fmt.Println("out2")
	case "long":
		fmt.Println(strings.Repeat("x", 2*1024*1024)) // longer than the scanner's limit
		fmt.Println("after")
	case "sleep":
		time.Sleep(time.Minute)
	case "fail":
		os.Exit(3)
	}
	os.Exit(0)
}

func helper(mode string) *Process {
	return &Process{
		Name: "helper", Bin: os.Args[0], Args: []string{"-test.run=TestHelperProcess"},
		Env: []string{"CC_HELPER=" + mode},
	}
}

func TestProcessDeliversLines(t *testing.T) {
	var mu sync.Mutex
	var out, errs, both []string
	p := helper("lines")
	p.Restart = RestartPolicy{Initial: time.Millisecond, MaxRestarts: 0}
	p.OnStdout = func(l string) { mu.Lock(); out = append(out, l); mu.Unlock() }
	p.OnStderr = func(l string) { mu.Lock(); errs = append(errs, l); mu.Unlock() }
	p.OnLine = func(l string) { mu.Lock(); both = append(both, l); mu.Unlock() }
	var exits atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	p.OnExit = func(ExitInfo) {
		if exits.Add(1) == 1 {
			cancel() // one run is enough
		}
	}
	p.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if len(out) < 2 || out[0] != "out1" || out[1] != "out2" {
		t.Errorf("stdout lines: %v", out)
	}
	if len(errs) < 1 || errs[0] != "err1" {
		t.Errorf("stderr lines: %v", errs)
	}
	if len(both) < 3 {
		t.Errorf("OnLine got %v", both)
	}
}

func TestRestartPolicyLimit(t *testing.T) {
	p := helper("fail")
	p.Restart = RestartPolicy{Initial: time.Millisecond, Max: 2 * time.Millisecond, MaxRestarts: 2}
	var starts, exits atomic.Int32
	var last ExitInfo
	p.OnStart = func() { starts.Add(1) }
	p.OnExit = func(i ExitInfo) { exits.Add(1); last = i }
	done := make(chan struct{})
	go func() { p.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after MaxRestarts")
	}
	if starts.Load() != 3 || exits.Load() != 3 {
		t.Errorf("starts %d exits %d, want 3 and 3 (1 run + 2 restarts)", starts.Load(), exits.Load())
	}
	if !last.Started || last.ExitCode != 3 || last.Err == nil {
		t.Errorf("exit info %+v", last)
	}
}

func TestStartFailureIsReported(t *testing.T) {
	p := &Process{Name: "missing", Bin: "/definitely/not/here", Restart: RestartPolicy{Initial: time.Millisecond, MaxRestarts: 1}}
	var infos []ExitInfo
	p.OnExit = func(i ExitInfo) { infos = append(infos, i) }
	p.Run(context.Background())
	if len(infos) != 2 {
		t.Fatalf("got %d exits, want 2", len(infos))
	}
	for _, i := range infos {
		if i.Started || i.Err == nil || i.ExitCode != -1 {
			t.Errorf("exit info %+v", i)
		}
	}
}

func TestContextCancelKillsProgram(t *testing.T) {
	p := helper("sleep")
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	p.OnStart = func() { started <- struct{}{} }
	h := p.Spawn(ctx)
	<-started
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	cancel()
	h.Stop(10 * time.Second)
	select {
	case <-h.Done():
	default:
		t.Fatal("process goroutine still running")
	}
	if time.Since(t0) > 5*time.Second {
		t.Errorf("stopping took %s", time.Since(t0))
	}
}

// Before v0.8 a line over the scanner limit stopped the reader, and the program then blocked
// forever on its next write to the full pipe.
func TestOverlongLineDoesNotBlockProgram(t *testing.T) {
	p := helper("long")
	p.Restart = RestartPolicy{Initial: time.Millisecond}
	var got atomic.Int32
	p.OnLine = func(string) { got.Add(1) }
	ctx, cancel := context.WithCancel(context.Background())
	p.OnExit = func(ExitInfo) { cancel() }
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("program blocked on its output pipe")
	}
}

func TestBackoffGrowsAndResets(t *testing.T) {
	// two quick failures with Initial 20ms must take at least 20ms + 40ms of waiting
	p := helper("fail")
	p.Restart = RestartPolicy{Initial: 20 * time.Millisecond, Max: time.Second, MaxRestarts: 2}
	t0 := time.Now()
	p.Run(context.Background())
	if d := time.Since(t0); d < 55*time.Millisecond {
		t.Errorf("restarts were not spaced out: %s", d)
	}
}

func TestFreePortPrefersRangeAndReleases(t *testing.T) {
	a := NewPortAllocator(18801, 18803)
	p1, p2, p3 := a.Free(), a.Free(), a.Free()
	for _, p := range []int{p1, p2, p3} {
		if p < 18801 || p > 18803 {
			t.Fatalf("port %d outside the preferred range", p)
		}
	}
	if p1 == p2 || p2 == p3 || p1 == p3 {
		t.Fatalf("same port handed out twice: %d %d %d", p1, p2, p3)
	}
	// the range is used up: the fallback is some other free port
	if p4 := a.Free(); p4 >= 18801 && p4 <= 18803 {
		t.Errorf("range exhausted but got %d", p4)
	}
	a.Release(p2)
	if p5 := a.Free(); p5 != p2 {
		t.Errorf("released port %d not reused (got %d)", p2, p5)
	}
}

func TestFreePortSkipsPortsInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:18811")
	if err != nil {
		t.Skip("port 18811 is busy here")
	}
	defer l.Close()
	a := NewPortAllocator(18811, 18812)
	if p := a.Free(); p != 18812 {
		t.Errorf("got %d, want 18812 (18811 is in use)", p)
	}
}

func TestDefaultPortRangeIs88xx(t *testing.T) {
	if Ports.Lo != 8801 || Ports.Hi != 8899 {
		t.Errorf("default range %d-%d, want 8801-8899", Ports.Lo, Ports.Hi)
	}
}

func TestFindBinary(t *testing.T) {
	dir := t.TempDir()
	name := "cc-fake-tool" + ExeSuffix()
	path := dir + string(os.PathSeparator) + name
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindBinary(path, "nothing"); got != path {
		t.Errorf("explicit path: %q", got)
	}
	if got := FindBinaryIn("", []string{dir}, "cc-fake-tool"); got == "" {
		t.Error("extra directory not searched")
	}
	if got := FindBinary("", "cc-no-such-tool-anywhere"); got != "" {
		t.Errorf("found %q", got)
	}
}
