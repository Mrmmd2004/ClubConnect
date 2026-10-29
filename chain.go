package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Chain is "Cloudflare -> Psiphon" / "Cloudflare -> Tor": the in-process WARP tunnel is exposed
// to the second engine as a private SOCKS5 port (the gate), and that engine is told to use it
// as its upstream proxy. Everything the engine sends - its handshake with Psiphon servers or
// Tor relays, and so your traffic inside - therefore leaves through Cloudflare first.
type Chain struct {
	name  string
	w     *Warp
	inner Backend
	setUp func(hostport string)

	mu       sync.Mutex
	cancel   context.CancelFunc
	startErr atomic.Value // string
}

func NewChainPsiphon(cfg *Config) *Chain {
	p := NewPsiphon(cfg)
	return &Chain{name: "warp+psiphon", w: NewWarp(cfg), inner: p,
		setUp: func(hp string) { p.Upstream = "socks5://" + hp }}
}

func NewChainTor(cfg *Config) *Chain {
	t := NewTor(cfg)
	return &Chain{name: "warp+tor", w: NewWarp(cfg), inner: t,
		setUp: func(hp string) { t.Upstream = hp }}
}

func (c *Chain) Name() string      { return c.name }
func (c *Chain) SupportsUDP() bool { return false }
func (c *Chain) Ready() bool       { return c.inner.Ready() }

func (c *Chain) LastError() string {
	if s, _ := c.startErr.Load().(string); s != "" {
		return s
	}
	if !c.w.Ready() {
		if e := c.w.LastError(); e != "" {
			return "warp: " + e
		}
		return "waiting for Cloudflare WARP"
	}
	return c.inner.LastError()
}

func (c *Chain) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return c.inner.DialTCP(ctx, addr)
}

func (c *Chain) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.New(c.name + " has no UDP")
}

func (c *Chain) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort())))
	if err != nil {
		return err
	}
	cctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	c.setUp(ln.Addr().String())
	if err := c.w.Start(cctx); err != nil {
		cancel()
		ln.Close()
		return err
	}
	go serveGate(cctx, ln, c.w)
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for !c.w.Ready() {
			select {
			case <-cctx.Done():
				return
			case <-t.C:
			}
		}
		log.Printf("[chain] Cloudflare WARP is up, starting %s through it", c.inner.Name())
		if err := c.inner.Start(cctx); err != nil {
			log.Printf("[%s] %v", c.inner.Name(), err)
			c.startErr.Store(err.Error())
		}
	}()
	return nil
}

func (c *Chain) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.inner.Stop()
	c.w.Stop()
}

// ---------- the gate: a minimal SOCKS5 (CONNECT only, no auth) onto the WARP tunnel ----------

func serveGate(ctx context.Context, ln net.Listener, w *Warp) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go gateConn(ctx, c, w)
	}
}

func gateConn(ctx context.Context, c net.Conn, w *Warp) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil || h[0] != 5 {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	rq := make([]byte, 4)
	if _, err := io.ReadFull(br, rq); err != nil || rq[0] != 5 {
		return
	}
	host, _, err := readAddr(br, rq[3])
	if err != nil {
		socksReply(c, 8, nil)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	if rq[1] != 1 {
		socksReply(c, 7, nil)
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	up, err := w.DialTCP(dctx, net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		socksReply(c, 5, nil)
		return
	}
	socksReply(c, 0, nil)
	c.SetReadDeadline(zeroTime)
	splice(c, br, up)
}
