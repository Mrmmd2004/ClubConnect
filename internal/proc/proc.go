// Package proc runs and supervises the helper programs (psiphon-tunnel-core, tor, aether): it
// finds them, hands them local ports, restarts them with backoff when they die and delivers
// their output line by line.
package proc

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"clubconnect/internal/logx"
)

// RestartPolicy says how a dying program is relaunched. The wait before a restart starts at
// Initial and doubles after each restart until it reaches Max; a run that lasted ResetAfter
// resets it. Zero fields take the defaults below, which are what Club Connect always used.
type RestartPolicy struct {
	Initial     time.Duration // default 1s
	Max         time.Duration // default 30s
	ResetAfter  time.Duration // default 1m
	MaxRestarts int           // 0 = restart forever
}

// DefaultRestart is the policy used when Process.Restart is left empty.
var DefaultRestart = RestartPolicy{Initial: time.Second, Max: 30 * time.Second, ResetAfter: time.Minute}

func (p RestartPolicy) withDefaults() RestartPolicy {
	if p.Initial <= 0 {
		p.Initial = DefaultRestart.Initial
	}
	if p.Max <= 0 {
		p.Max = DefaultRestart.Max
	}
	if p.ResetAfter <= 0 {
		p.ResetAfter = DefaultRestart.ResetAfter
	}
	return p
}

// ExitInfo describes one run of the program, passed to OnExit.
type ExitInfo struct {
	Err      error         // from starting or waiting for the program; nil after a clean exit
	Started  bool          // false when the program could not be launched at all
	Ran      time.Duration // how long it ran
	ExitCode int           // -1 when unknown (not started, or killed by a signal)
}

// Process is an external program that is kept running. Fill the exported fields and call Run.
type Process struct {
	Name string // used in log lines
	Bin  string
	Args []string
	Env  []string // added to the environment of Club Connect

	Restart RestartPolicy

	OnStart  func()            // right before each launch
	OnStdout func(line string) // each stdout line
	OnStderr func(line string) // each stderr line
	OnLine   func(line string) // each line of either stream (after OnStdout / OnStderr)
	OnExit   func(ExitInfo)    // when a run ends, before the restart wait
}

// Run launches the program and relaunches it per the restart policy until ctx ends (which also
// kills the running program) or MaxRestarts is reached. It blocks.
func (p *Process) Run(ctx context.Context) {
	pol := p.Restart.withDefaults()
	log := logx.For(p.Name)
	backoff := pol.Initial
	restarts := 0
	for ctx.Err() == nil {
		info := p.runOnce(ctx, log)
		if p.OnExit != nil {
			p.OnExit(info)
		}
		if pol.MaxRestarts > 0 && restarts >= pol.MaxRestarts {
			return
		}
		restarts++
		if info.Ran > pol.ResetAfter {
			backoff = pol.Initial
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < pol.Max {
			backoff *= 2
		}
	}
}

func (p *Process) runOnce(ctx context.Context, log logx.Logger) ExitInfo {
	started := time.Now()
	cmd := exec.CommandContext(ctx, p.Bin, p.Args...)
	cmd.Env = append(os.Environ(), p.Env...)
	HideWindow(cmd)
	if p.OnStart != nil {
		p.OnStart()
	}
	so, _ := cmd.StdoutPipe()
	se, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		log.Warnf("cannot start: %v", err)
		return ExitInfo{Err: err, ExitCode: -1}
	}
	var wg sync.WaitGroup
	for _, s := range []struct {
		r  io.Reader
		fn func(string)
	}{{so, p.OnStdout}, {se, p.OnStderr}} {
		wg.Add(1)
		go func(r io.Reader, fn func(string)) {
			defer wg.Done()
			pump(r, fn, p.OnLine)
		}(s.r, s.fn)
	}
	wg.Wait()
	err := cmd.Wait()
	info := ExitInfo{Err: err, Started: true, Ran: time.Since(started), ExitCode: -1}
	var ee *exec.ExitError
	if err == nil {
		info.ExitCode = 0
	} else if errors.As(err, &ee) {
		info.ExitCode = ee.ExitCode()
	}
	log.Infof("process exited")
	return info
}

// pump hands every line of r to the callbacks. After a line too long for the scanner it keeps
// draining r: a program whose output pipe is no longer read blocks forever on its next write.
func pump(r io.Reader, fns ...func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		for _, fn := range fns {
			if fn != nil {
				fn(sc.Text())
			}
		}
	}
	io.Copy(io.Discard, r)
}

// Handle is a Process running in the background.
type Handle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Spawn runs p in a goroutine under a child context of ctx and returns at once.
func (p *Process) Spawn(ctx context.Context) *Handle {
	cctx, cancel := context.WithCancel(ctx)
	h := &Handle{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(h.done)
		p.Run(cctx)
	}()
	return h
}

// Done is closed when the process goroutine has ended.
func (h *Handle) Done() <-chan struct{} { return h.done }

// Stop kills the program and waits for the goroutine to end, but not longer than wait.
func (h *Handle) Stop(wait time.Duration) {
	h.cancel()
	if wait <= 0 {
		return
	}
	select {
	case <-h.done:
	case <-time.After(wait):
	}
}
