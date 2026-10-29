package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

// proc runs an external program and restarts it with backoff if it dies.
type proc struct {
	name   string
	bin    string
	args   []string
	env    []string
	onStart func()            // called right before each launch
	onLine  func(line string) // called for each stdout/stderr line
	onExit  func()            // called when the process ends (before restart)
}

func (p *proc) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		cmd := exec.CommandContext(ctx, p.bin, p.args...)
		cmd.Env = append(os.Environ(), p.env...)
		hideWindow(cmd)
		if p.onStart != nil {
			p.onStart()
		}
		so, _ := cmd.StdoutPipe()
		se, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			log.Printf("[%s] cannot start: %v", p.name, err)
		} else {
			var wg sync.WaitGroup
			for _, r := range []io.Reader{so, se} {
				wg.Add(1)
				go func(r io.Reader) {
					defer wg.Done()
					sc := bufio.NewScanner(r)
					sc.Buffer(make([]byte, 64*1024), 1024*1024)
					for sc.Scan() {
						if p.onLine != nil {
							p.onLine(sc.Text())
						}
					}
				}(r)
			}
			wg.Wait()
			cmd.Wait()
			log.Printf("[%s] process exited", p.name)
		}
		if p.onExit != nil {
			p.onExit()
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// findBinary looks for a helper: explicit path, next to our executable, ./bin, then PATH.
func findBinary(explicit string, names ...string) string {
	return findBinaryIn(explicit, nil, names...)
}

// findBinaryIn is findBinary with extra directories searched before PATH.
func findBinaryIn(explicit string, extra []string, names ...string) string {
	if explicit != "" {
		if st, err := os.Stat(explicit); err == nil && !st.IsDir() {
			return explicit
		}
	}
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		dirs = append(dirs, d, filepath.Join(d, "bin"))
	}
	dirs = append(dirs, ".", "bin")
	dirs = append(dirs, extra...)
	for _, n := range names {
		if runtime.GOOS == "windows" {
			n += ".exe"
		}
		for _, d := range dirs {
			p := filepath.Join(d, n)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				abs, _ := filepath.Abs(p)
				return abs
			}
		}
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// freePort prefers the 88xx range (8801-8899) for the helper processes, then any free port.
func freePort() int {
	for p := 8801; p <= 8899; p++ {
		if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); err == nil {
			l.Close()
			if !usedPorts.claim(p) {
				continue
			}
			return p
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// two helpers must never be handed the same port before they have bound it
type portSet struct {
	mu sync.Mutex
	m  map[int]bool
}

func (s *portSet) claim(p int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[int]bool{}
	}
	if s.m[p] {
		return false
	}
	s.m[p] = true
	return true
}

var usedPorts portSet
