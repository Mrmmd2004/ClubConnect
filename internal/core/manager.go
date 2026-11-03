package core

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"clubconnect/internal/logx"
)

// DefaultHealthURLs are fetched through a backend to test it.
var DefaultHealthURLs = []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"}

// Options configures a Manager. Zero values mean the defaults.
type Options struct {
	Verbose        func() bool   // read live: show every failed connection
	HealthURLs     []string      // default DefaultHealthURLs
	HealthInterval time.Duration // between two health rounds; default 30s
	FirstProbe     time.Duration // delay of the first health round; default 3s
	Pin            string        // start pinned to the backend with this name ("" = auto)
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

// Manager owns a set of backends: it starts them, tests them regularly, keeps the best one
// active and dials through the active one first, falling back to the others.
type Manager struct {
	opts   Options
	bs     []*bstate
	active atomic.Int32 // index into bs, -1 = none yet
	mode   atomic.Value // string: "auto" or the name of the pinned backend
	up     atomic.Uint64
	down   atomic.Uint64
	kick   chan struct{}

	failMu sync.Mutex
	failAt map[string]time.Time
}

func NewManager(opts Options, backends []Backend) *Manager {
	if len(opts.HealthURLs) == 0 {
		opts.HealthURLs = DefaultHealthURLs
	}
	if opts.HealthInterval <= 0 {
		opts.HealthInterval = 30 * time.Second // config.Validate already keeps real settings at 5 s or more
	}
	if opts.FirstProbe <= 0 {
		opts.FirstProbe = 3 * time.Second
	}
	m := &Manager{opts: opts, kick: make(chan struct{}, 1), failAt: map[string]time.Time{}}
	for _, b := range backends {
		m.bs = append(m.bs, &bstate{b: b})
	}
	m.active.Store(-1)
	m.mode.Store("auto") // the Controller pins a single backend when a manual mode is chosen
	if opts.Pin != "" {
		m.mode.Store(opts.Pin)
	}
	return m
}

func (m *Manager) verbose() bool { return m.opts.Verbose != nil && m.opts.Verbose() }

// pinned returns the index of the backend the mode is pinned to, or -1 (auto, or no such one).
func (m *Manager) pinned() int {
	pin, _ := m.mode.Load().(string)
	if pin == "" || pin == "auto" {
		return -1
	}
	for i, s := range m.bs {
		if s.b.Name() == pin {
			return i
		}
	}
	return -1
}

// SetMode pins the manager to one backend by name, or back to "auto".
func (m *Manager) SetMode(v string) error {
	if v != "auto" {
		ok := false
		for _, s := range m.bs {
			if s.b.Name() == v {
				ok = true
			}
		}
		if !ok {
			return ErrUnknownBackend
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
	if i := m.pinned(); i >= 0 {
		first = m.bs[i]
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

func (c *countConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// note counts a dial result: three failures in a row mark the backend unhealthy at once and
// wake the health loop, which then tests it for real.
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
// them with verbose on.
func (m *Manager) logFail(name, addr string, err error) {
	m.failMu.Lock()
	now := time.Now()
	show := m.verbose() || now.Sub(m.failAt[name]) > 20*time.Second
	if show {
		m.failAt[name] = now
	}
	m.failMu.Unlock()
	if show {
		logx.For(name).Infof("cannot reach %s: %v", addr, err)
	}
}

func (m *Manager) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var last error = ErrNoBackend
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
	var last error = ErrNoUDPBackend
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
	if hc, ok := s.b.(HealthChecker); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return hc.Health(ctx)
	}
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
	for _, u := range m.opts.HealthURLs {
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
				logx.For(s.b.Name()).Infof("healthy=%v", ok)
			}
			s.healthy = ok
			s.mu.Unlock()
		}(s)
	}
	wg.Wait()
	m.pick()
}

// pick applies Pick to the current health picture. A pinned backend is always the active one.
func (m *Manager) pick() {
	if i := m.pinned(); i >= 0 {
		m.active.Store(int32(i))
		return
	}
	cs := make([]Candidate, len(m.bs))
	for i, s := range m.bs {
		cs[i].Healthy, cs[i].Latency = s.snapshot()
	}
	cur := int(m.active.Load())
	next, ok := Pick(cs, cur)
	if ok && next != cur {
		logx.For("manager").Infof("active backend: %s", m.bs[next].b.Name())
		m.active.Store(int32(next))
	}
}

// Run starts every backend and then keeps testing them until ctx ends, when it stops them.
func (m *Manager) Run(ctx context.Context) {
	for _, s := range m.bs {
		if err := s.b.Start(ctx); err != nil {
			logx.For(s.b.Name()).Infof("disabled: %v", err)
		}
	}
	fast := time.NewTimer(m.opts.FirstProbe)
	slow := time.NewTicker(m.opts.HealthInterval)
	defer slow.Stop()
	defer fast.Stop()
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
				fast.Reset(m.opts.FirstProbe) // keep polling quickly until the first one works
			}
		case <-slow.C:
			m.probeAll()
		case <-m.kick:
			m.probeAll()
		}
	}
}

// Status is the manager's part of GET /status (the Controller adds version, ports and modes).
func (m *Manager) Status() Status {
	st := Status{Up: m.up.Load(), Down: m.down.Load(), Backends: []BackendStatus{}}
	st.Mode, _ = m.mode.Load().(string)
	if i := int(m.active.Load()); i >= 0 && i < len(m.bs) {
		st.Active = m.bs[i].b.Name()
	}
	for _, s := range m.bs {
		h, l := s.snapshot()
		st.Backends = append(st.Backends, BackendStatus{
			Name: s.b.Name(), Ready: s.b.Ready(), Healthy: h,
			LatencyMS: l.Milliseconds(), UDP: s.b.SupportsUDP(), Variant: VariantOf(s.b), Error: s.b.LastError(),
		})
	}
	return st
}
