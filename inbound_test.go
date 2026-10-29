package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// direct backend: dials the real network, used to test the proxy front end in isolation
type direct struct{ ready bool }

func (d *direct) Name() string                { return "direct" }
func (d *direct) Start(context.Context) error { return nil }
func (d *direct) Ready() bool                 { return true }
func (d *direct) LastError() string           { return "" }
func (d *direct) SupportsUDP() bool           { return true }
func (d *direct) Stop()                       {}
func (d *direct) DialTCP(ctx context.Context, a string) (net.Conn, error) {
	var dl net.Dialer
	return dl.DialContext(ctx, "tcp", a)
}
func (d *direct) DialUDP(ctx context.Context, a string) (net.Conn, error) {
	var dl net.Dialer
	return dl.DialContext(ctx, "udp", a)
}

func startProxy(t *testing.T, user, pass string) (string, context.CancelFunc) {
	cfg := defaultConfig()
	cfg.Listen, cfg.Username, cfg.Password = "127.0.0.1", user, pass
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg.Port = l.Addr().(*net.TCPAddr).Port
	l.Close()
	m := NewManager(cfg, []Backend{&direct{}})
	m.active.Store(0)
	ctx, cancel := context.WithCancel(context.Background())
	go (&Inbound{m: m, cfg: cfg}).Serve(ctx)
	time.Sleep(100 * time.Millisecond)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)), cancel
}

func echoTCP(t *testing.T) string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

func socksConnect(t *testing.T, proxy, target string, auth bool, user, pass string) net.Conn {
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		c.Write([]byte{5, 1, 2})
		b := make([]byte, 2)
		io.ReadFull(c, b)
		if b[1] != 2 {
			t.Fatalf("method %v", b)
		}
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(msg, byte(len(pass)))
		c.Write(append(msg, pass...))
		io.ReadFull(c, b)
		if b[1] != 0 {
			t.Fatalf("auth rejected")
		}
	} else {
		c.Write([]byte{5, 1, 0})
		b := make([]byte, 2)
		io.ReadFull(c, b)
	}
	host, ps, _ := net.SplitHostPort(target)
	p, _ := strconv.Atoi(ps)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(p>>8), byte(p))
	c.Write(req)
	r := make([]byte, 10)
	io.ReadFull(c, r)
	if r[1] != 0 {
		t.Fatalf("connect failed: %d", r[1])
	}
	return c
}

func TestSocksConnect(t *testing.T) {
	proxy, stop := startProxy(t, "", "")
	defer stop()
	c := socksConnect(t, proxy, echoTCP(t), false, "", "")
	defer c.Close()
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	io.ReadFull(c, b)
	if string(b) != "hello" {
		t.Fatalf("got %q", b)
	}
}

func TestSocksAuth(t *testing.T) {
	proxy, stop := startProxy(t, "u", "p")
	defer stop()
	c := socksConnect(t, proxy, echoTCP(t), true, "u", "p")
	c.Close()
	c2, _ := net.Dial("tcp", proxy)
	defer c2.Close()
	c2.Write([]byte{5, 1, 0}) // no-auth offered while auth is required
	b := make([]byte, 2)
	io.ReadFull(c2, b)
	if b[1] != 0xFF {
		t.Fatalf("expected rejection, got %v", b)
	}
}

func TestHTTPProxy(t *testing.T) {
	proxy, stop := startProxy(t, "", "")
	defer stop()
	echo := echoTCP(t)
	c, _ := net.Dial("tcp", proxy)
	defer c.Close()
	c.Write([]byte("CONNECT " + echo + " HTTP/1.1\r\nHost: " + echo + "\r\n\r\n"))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("connect: %v %v", resp, err)
	}
	c.Write([]byte("ping"))
	b := make([]byte, 4)
	io.ReadFull(br, b)
	if string(b) != "ping" {
		t.Fatalf("got %q", b)
	}
}

func TestHTTPPlain(t *testing.T) {
	proxy, stop := startProxy(t, "", "")
	defer stop()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok:"+r.URL.Path) })}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(l)
	defer srv.Close()
	pu, _ := url.Parse("http://" + proxy)
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := cl.Get("http://" + l.Addr().String() + "/x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok:/x" {
		t.Fatalf("got %q", b)
	}
}

func TestUDPAssociate(t *testing.T) {
	proxy, stop := startProxy(t, "", "")
	defer stop()
	ue, _ := net.ListenPacket("udp", "127.0.0.1:0")
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := ue.ReadFrom(buf)
			if err != nil {
				return
			}
			ue.WriteTo(buf[:n], a)
		}
	}()
	ctl, _ := net.Dial("tcp", proxy)
	defer ctl.Close()
	ctl.Write([]byte{5, 1, 0})
	b := make([]byte, 2)
	io.ReadFull(ctl, b)
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	r := make([]byte, 10)
	io.ReadFull(ctl, r)
	if r[1] != 0 {
		t.Fatalf("assoc failed %v", r)
	}
	relay := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(r[8:10]))}
	uc, _ := net.DialUDP("udp", nil, relay)
	defer uc.Close()
	dst := ue.LocalAddr().(*net.UDPAddr)
	pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(dst.Port >> 8), byte(dst.Port)}
	uc.Write(append(pkt, []byte("dns?")...))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[10:n]) != "dns?" {
		t.Fatalf("got %q", buf[:n])
	}
}
