package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type warpIdentity struct {
	PrivateKey string `json:"private_key"` // base64
	PeerPublic string `json:"peer_public_key"`
	V4         string `json:"v4"`
	V6         string `json:"v6"`
}

type warpSession struct {
	dev  *device.Device
	tnet *netstack.Net
	ep   string
}

func (s *warpSession) close() { s.dev.Close() }

type Warp struct {
	cfg  *Config
	dir  string
	sess atomic.Pointer[warpSession]
	err  atomic.Value
}

func NewWarp(cfg *Config) *Warp { return &Warp{cfg: cfg, dir: cfg.DataDir} }

func (w *Warp) Name() string      { return "warp" }
func (w *Warp) SupportsUDP() bool { return true }
func (w *Warp) Ready() bool       { return w.sess.Load() != nil }
func (w *Warp) LastError() string { s, _ := w.err.Load().(string); return s }
func (w *Warp) Stop() {
	if s := w.sess.Swap(nil); s != nil {
		s.close()
	}
}

func (w *Warp) setErr(err error) {
	w.err.Store(err.Error())
	log.Printf("[warp] %v", err)
}

func (w *Warp) Start(ctx context.Context) error {
	go w.run(ctx)
	return nil
}

func (w *Warp) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	s := w.sess.Load()
	if s == nil {
		return nil, errors.New("warp not connected")
	}
	return s.tnet.DialContext(ctx, "tcp", addr)
}

func (w *Warp) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	s := w.sess.Load()
	if s == nil {
		return nil, errors.New("warp not connected")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := s.tnet.LookupContextHost(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: %v", host, err)
		}
		if ip, err = netip.ParseAddr(ips[0]); err != nil {
			return nil, err
		}
	}
	var p uint16
	fmt.Sscanf(port, "%d", &p)
	return s.tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(ip, p))
}

// run: identity -> connect -> watch, forever, with backoff (kind to Cloudflare's rate limits).
func (w *Warp) run(ctx context.Context) {
	backoff := 3 * time.Second
	sleep := func() bool {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		if backoff < 90*time.Second {
			backoff *= 2
		}
		return true
	}
	for ctx.Err() == nil {
		id, err := w.identity(ctx)
		if err != nil {
			w.setErr(err)
			if !sleep() {
				return
			}
			continue
		}
		s, err := w.connect(ctx, id)
		if err != nil {
			w.setErr(err)
			if !sleep() {
				return
			}
			continue
		}
		backoff = 3 * time.Second
		w.err.Store("")
		w.sess.Store(s)
		log.Printf("[warp] connected via %s", s.ep)
		w.watch(ctx, s)
		w.sess.Store(nil)
		s.close()
		log.Printf("[warp] connection lost, reconnecting")
	}
}

// watch declares the session dead after 3 failed in-tunnel probes in a row.
func (w *Warp) watch(ctx context.Context, s *warpSession) {
	fails := 0
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := s.tnet.DialContext(pctx, "tcp", "1.1.1.1:443")
		cancel()
		if err == nil {
			c.Close()
			fails = 0
			continue
		}
		if fails++; fails >= 3 {
			return
		}
	}
}

// ---------- identity ----------

func (w *Warp) identity(ctx context.Context) (*warpIdentity, error) {
	if p := w.cfg.Warp.WGConf; p != "" {
		return parseWGConf(p)
	}
	path := filepath.Join(w.dir, "warp-identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var id warpIdentity
		if json.Unmarshal(b, &id) == nil && id.PrivateKey != "" && id.PeerPublic != "" {
			return &id, nil
		}
	}
	log.Printf("[warp] registering a free device (saved to %s)", path)
	id, err := warpRegister(ctx)
	if err != nil {
		return nil, fmt.Errorf("registration failed (set warp.wg_conf to a wgcf profile if blocked): %w", err)
	}
	b, _ := json.MarshalIndent(id, "", "  ")
	os.WriteFile(path, b, 0o600)
	return id, nil
}

func warpRegister(ctx context.Context) (*warpIdentity, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{
		"key":        base64.StdEncoding.EncodeToString(pub),
		"install_id": "",
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":      "PC",
		"type":       "Android",
		"locale":     "en_US",
	})
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.cloudflareclient.com/v0a2158/reg", bytes.NewReader(body))
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.3-2158")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return nil, errors.New("rate limited by Cloudflare (HTTP 429); will retry later")
	}
	var r struct {
		Config struct {
			Peers []struct {
				PublicKey string `json:"public_key"`
			} `json:"peers"`
			Interface struct {
				Addresses struct {
					V4 string `json:"v4"`
					V6 string `json:"v6"`
				} `json:"addresses"`
			} `json:"interface"`
		} `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if len(r.Config.Peers) == 0 || r.Config.Interface.Addresses.V4 == "" {
		return nil, fmt.Errorf("unexpected response (HTTP %d)", resp.StatusCode)
	}
	return &warpIdentity{
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PeerPublic: r.Config.Peers[0].PublicKey,
		V4:         r.Config.Interface.Addresses.V4,
		V6:         r.Config.Interface.Addresses.V6,
	}, nil
}

func parseWGConf(path string) (*warpIdentity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	id := &warpIdentity{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "privatekey":
			id.PrivateKey = v
		case "publickey":
			id.PeerPublic = v
		case "address":
			for _, p := range strings.Split(v, ",") {
				if p = strings.TrimSpace(p); strings.Contains(p, ":") {
					id.V6 = p
				} else {
					id.V4 = p
				}
			}
		}
	}
	if id.PrivateKey == "" || id.PeerPublic == "" || id.V4 == "" {
		return nil, errors.New("incomplete WireGuard profile")
	}
	return id, nil
}

// ---------- endpoint discovery ----------

func (w *Warp) candidates() []string {
	seen := map[string]bool{}
	var out []string
	add := func(e string) {
		e = strings.TrimSpace(e)
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if b, err := os.ReadFile(filepath.Join(w.dir, "warp-endpoint.txt")); err == nil {
		add(string(b)) // last known good first: reconnects are instant
	}
	for _, e := range w.cfg.Warp.Endpoints {
		add(e)
	}
	if ips, err := net.LookupHost("engage.cloudflareclient.com"); err == nil {
		for _, ip := range ips {
			add(net.JoinHostPort(ip, "2408"))
		}
	}
	ports := []string{"2408", "500", "4500", "854", "1701"}
	for _, ip := range []string{"162.159.192.1", "162.159.193.1", "162.159.195.1", "188.114.96.1", "188.114.97.1", "188.114.98.1", "188.114.99.1"} {
		for _, p := range ports {
			add(net.JoinHostPort(ip, p))
		}
	}
	return out
}

// connect races several endpoints in parallel; the first that passes a real HTTP test wins.
func (w *Warp) connect(ctx context.Context, id *warpIdentity) (*warpSession, error) {
	eps := w.candidates()
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := make(chan *warpSession, 1)
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
loop:
	for _, ep := range eps {
		select {
		case sem <- struct{}{}:
		case <-cctx.Done():
			break loop
		}
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			defer func() { <-sem }()
			s, err := tryEndpoint(cctx, id, ep)
			if err != nil {
				return
			}
			select {
			case found <- s:
				cancel()
			default:
				s.close()
			}
		}(ep)
	}
	wg.Wait()
	select {
	case s := <-found:
		os.WriteFile(filepath.Join(w.dir, "warp-endpoint.txt"), []byte(s.ep), 0o600)
		return s, nil
	default:
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("no WARP endpoint answered (network may block UDP to Cloudflare)")
	}
}

func tryEndpoint(ctx context.Context, id *warpIdentity, ep string) (*warpSession, error) {
	priv, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(id.PeerPublic)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	for _, a := range []string{id.V4, id.V6} {
		if a == "" {
			continue
		}
		if p, err := netip.ParsePrefix(a); err == nil {
			addrs = append(addrs, p.Addr())
		} else if x, err := netip.ParseAddr(a); err == nil {
			addrs = append(addrs, x)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("no tunnel address")
	}
	tun, tnet, err := netstack.CreateNetTUN(addrs,
		[]netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}, 1280)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint=%s\npersistent_keepalive_interval=25\n",
		hex.EncodeToString(priv), hex.EncodeToString(pub), ep)
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	cl := &http.Client{
		Timeout:   6 * time.Second,
		Transport: &http.Transport{DialContext: tnet.DialContext, DisableKeepAlives: true},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://cp.cloudflare.com/generate_204", nil)
	resp, err := cl.Do(req)
	if err != nil {
		dev.Close()
		return nil, err
	}
	resp.Body.Close()
	return &warpSession{dev: dev, tnet: tnet, ep: ep}, nil
}
