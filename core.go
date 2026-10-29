package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Backend interface {
	Name() string
	Start(ctx context.Context) error // must not block: supervision runs in goroutines
	Ready() bool
	LastError() string
	SupportsUDP() bool
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
	Stop()
}

type bstate struct {
	b       Backend
	mu      sync.Mutex
	healthy bool
	lat     time.Duration
	fails   int
}

func (s *bstate) snapshot() (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy, s.lat
}

type Manager struct {
	cfg    *Config
	bs     []*bstate
	active atomic.Int32 // index into bs, -1 = none yet
	mode   atomic.Value // string
	up     atomic.Uint64
	down   atomic.Uint64
	kick   chan struct{}

	failMu sync.Mutex
	failAt map[string]time.Time
}

func NewManager(cfg *Config, backends []Backend) *Manager {
	m := &Manager{cfg: cfg, kick: make(chan struct{}, 1), failAt: map[string]time.Time{}}
	for _, b := range backends {
		m.bs = append(m.bs, &bstate{b: b})
	}
	m.active.Store(-1)
	m.mode.Store("auto") // the Controller pins a single backend when a manual mode is chosen
	return m
}

func (m *Manager) SetMode(v string) error {
	if v != "auto" {
		ok := false
		for _, s := range m.bs {
			if s.b.Name() == v {
				ok = true
			}
		}
		if !ok {
			return errors.New("unknown backend")
		}
	}
	m.mode.Store(v)
	m.pick()
	return nil
}

// candidates: ready backends, preferred first.
func (m *Manager) candidates(udp bool) []*bstate {
	var first *bstate
	if i := int(m.active.Load()); i >= 0 && i < len(m.bs) {
		first = m.bs[i]
	}
	if pin, _ := m.mode.Load().(string); pin != "" && pin != "auto" {
		for _, s := range m.bs {
			if s.b.Name() == pin {
				first = s
			}
		}
	}
	var out []*bstate
	add := func(s *bstate) {
		if s == nil || !s.b.Ready() || (udp && !s.b.SupportsUDP()) {
			return
		}
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	add(first)
	for _, s := range m.bs {
		add(s)
	}
	return out
}

type countConn struct {
	net.Conn
	m *Manager
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.m.down.Add(uint64(n))
	return n, err
}
func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.m.up.Add(uint64(n))
	return n, err
}

func (m *Manager) note(s *bstate, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.fails = 0
		return
	}
	s.fails++
	if s.fails >= 3 && s.healthy {
		s.healthy = false
		select {
		case m.kick <- struct{}{}:
		default:
		}
	}
}

// logFail makes failed connections visible: the first one per backend every 20 s, or all of
// them with verbose on. Before this the core failed silently.
func (m *Manager) logFail(name, addr string, err error) {
	m.failMu.Lock()
	now := time.Now()
	show := m.cfg.Verbose || now.Sub(m.failAt[name]) > 20*time.Second
	if show {
		m.failAt[name] = now
	}
	m.failMu.Unlock()
	if show {
		log.Printf("[%s] cannot reach %s: %v", name, addr, err)
	}
}

func (m *Manager) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var last error = errors.New("no backend is ready yet")
	for _, s := range m.candidates(false) {
		dctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		c, err := s.b.DialTCP(dctx, addr)
		cancel()
		m.note(s, err)
		if err == nil {
			return &countConn{c, m}, nil
		}
		m.logFail(s.b.Name(), addr, err)
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (m *Manager) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	var last error = errors.New("no UDP-capable backend is ready")
	for _, s := range m.candidates(true) {
		dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		c, err := s.b.DialUDP(dctx, addr)
		cancel()
		if err == nil {
			return &countConn{c, m}, nil
		}
		last = err
	}
	return nil, last
}

func (m *Manager) probe(s *bstate) (time.Duration, bool) {
	cl := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, a string) (net.Conn, error) {
				return s.b.DialTCP(ctx, a)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, u := range m.cfg.HealthURLs {
		t0 := time.Now()
		resp, err := cl.Get(u)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return time.Since(t0), true
		}
	}
	return 0, false
}

func (m *Manager) probeAll() {
	var wg sync.WaitGroup
	for _, s := range m.bs {
		if !s.b.Ready() {
			s.mu.Lock()
			s.healthy = false
			s.mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(s *bstate) {
			defer wg.Done()
			lat, ok := m.probe(s)
			s.mu.Lock()
			if ok {
				if s.lat == 0 {
					s.lat = lat
				} else {
					s.lat = (s.lat*2 + lat) / 3 // smooth jitter
				}
				s.fails = 0
			}
			if ok != s.healthy {
				log.Printf("[%s] healthy=%v", s.b.Name(), ok)
			}
			s.healthy = ok
			s.mu.Unlock()
		}(s)
	}
	wg.Wait()
	m.pick()
}

// pick keeps the current backend unless it is down or another is clearly faster.
func (m *Manager) pick() {
	if pin, _ := m.mode.Load().(string); pin != "" && pin != "auto" {
		for i, s := range m.bs {
			if s.b.Name() == pin {
				m.active.Store(int32(i))
				return
			}
		}
	}
	best := -1
	var bestLat time.Duration
	for i, s := range m.bs {
		h, l := s.snapshot()
		if h && (best < 0 || l < bestLat) {
			best, bestLat = i, l
		}
	}
	if best < 0 {
		return
	}
	cur := int(m.active.Load())
	if cur >= 0 && cur < len(m.bs) && cur != best {
		if h, l := m.bs[cur].snapshot(); h && l <= bestLat*14/10 {
			return // hysteresis: avoid flapping
		}
	}
	if cur != best {
		log.Printf("[manager] active backend: %s", m.bs[best].b.Name())
		m.active.Store(int32(best))
	}
}

func (m *Manager) Run(ctx context.Context) {
	for _, s := range m.bs {
		if err := s.b.Start(ctx); err != nil {
			log.Printf("[%s] disabled: %v", s.b.Name(), err)
		}
	}
	interval := time.Duration(m.cfg.HealthInterval) * time.Second
	fast := time.NewTimer(3 * time.Second)
	slow := time.NewTicker(interval)
	defer slow.Stop()
	anyHealthy := func() bool {
		for _, s := range m.bs {
			if h, _ := s.snapshot(); h {
				return true
			}
		}
		return false
	}
	for {
		select {
		case <-ctx.Done():
			for _, s := range m.bs {
				s.b.Stop()
			}
			return
		case <-fast.C:
			m.probeAll()
			if !anyHealthy() {
				fast.Reset(3 * time.Second) // keep polling quickly until the first one works
			}
		case <-slow.C:
			m.probeAll()
		case <-m.kick:
			m.probeAll()
		}
	}
}

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
