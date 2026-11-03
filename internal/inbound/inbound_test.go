package inbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// direct dials the real network: it tests the proxy front end in isolation.
type direct struct{}

func (direct) DialTCP(ctx context.Context, a string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", a)
}
func (direct) DialUDP(ctx context.Context, a string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "udp", a)
}

func startProxy(t *testing.T, user, pass string) (*Server, string, context.CancelFunc) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Dialer: direct{}, Auth: Auth{user, pass}}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx, l)
	return s, l.Addr().String(), cancel
}

func echoTCP(t *testing.T) string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { l.Close() })
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
	_, proxy, stop := startProxy(t, "", "")
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
	_, proxy, stop := startProxy(t, "u", "p")
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

func TestSocksWrongPassword(t *testing.T) {
	_, proxy, stop := startProxy(t, "u", "p")
	defer stop()
	c, _ := net.Dial("tcp", proxy)
	defer c.Close()
	c.Write([]byte{5, 1, 2})
	b := make([]byte, 2)
	io.ReadFull(c, b)
	c.Write([]byte{1, 1, 'u', 5, 'w', 'r', 'o', 'n', 'g'})
	io.ReadFull(c, b)
	if b[1] == 0 {
		t.Fatal("wrong password accepted")
	}
}

func TestSocksRefusedDestination(t *testing.T) {
	_, proxy, stop := startProxy(t, "", "")
	defer stop()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	c, _ := net.Dial("tcp", proxy)
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	host, ps, _ := net.SplitHostPort(dead)
	p, _ := strconv.Atoi(ps)
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	c.Write(append(req, byte(p>>8), byte(p)))
	r := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 5 {
		t.Errorf("reply %v err %v, want code 5 (connection refused)", r, err)
	}
}

func TestSocksUnsupportedCommand(t *testing.T) {
	_, proxy, stop := startProxy(t, "", "")
	defer stop()
	c, _ := net.Dial("tcp", proxy)
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80}) // BIND
	r := make([]byte, 10)
	io.ReadFull(c, r)
	if r[1] != 7 {
		t.Errorf("reply %v, want code 7", r)
	}
}

func TestHTTPProxy(t *testing.T) {
	_, proxy, stop := startProxy(t, "", "")
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
	_, proxy, stop := startProxy(t, "", "")
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

func TestHTTPProxyAuth(t *testing.T) {
	_, proxy, stop := startProxy(t, "u", "p")
	defer stop()
	echo := echoTCP(t)
	connect := func(hdr string) *http.Response {
		c, _ := net.Dial("tcp", proxy)
		t.Cleanup(func() { c.Close() })
		c.Write([]byte("CONNECT " + echo + " HTTP/1.1\r\nHost: " + echo + "\r\n" + hdr + "\r\n"))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := connect(""); r.StatusCode != 407 || r.Header.Get("Proxy-Authenticate") == "" {
		t.Errorf("no credentials: %d", r.StatusCode)
	}
	bad := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("u:nope")) + "\r\n"
	if r := connect(bad); r.StatusCode != 407 {
		t.Errorf("wrong password: %d", r.StatusCode)
	}
	good := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("u:p")) + "\r\n"
	if r := connect(good); r.StatusCode != 200 {
		t.Errorf("right password: %d", r.StatusCode)
	}
}

func TestHTTPBadGateway(t *testing.T) {
	_, proxy, stop := startProxy(t, "", "")
	defer stop()
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	c, _ := net.Dial("tcp", proxy)
	defer c.Close()
	c.Write([]byte("CONNECT " + dead + " HTTP/1.1\r\nHost: " + dead + "\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 502 {
		t.Errorf("got %v %v, want 502", resp, err)
	}
}

func TestUDPAssociate(t *testing.T) {
	_, proxy, stop := startProxy(t, "", "")
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

// Stopping a mode must cut the connections that went through it (before v0.8 they stayed open
// and kept using the old engine).
func TestShutdownClosesOpenConnections(t *testing.T) {
	s, proxy, stop := startProxy(t, "", "")
	c := socksConnect(t, proxy, echoTCP(t), false, "", "")
	defer c.Close()
	c.Write([]byte("a"))
	io.ReadFull(c, make([]byte, 1))
	deadline := time.Now().Add(2 * time.Second)
	for s.Open() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Open() != 1 {
		t.Fatalf("Open() = %d, want 1", s.Open())
	}
	stop()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("the connection survived the shutdown")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("the connection was still open after the shutdown (read timed out)")
	}
	deadline = time.Now().Add(2 * time.Second)
	for s.Open() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Open() != 0 {
		t.Errorf("Open() = %d after shutdown", s.Open())
	}
}

func TestAuthUnit(t *testing.T) {
	a := Auth{"u", "p"}
	if !a.Check("u", "p") || a.Check("u", "x") || a.Check("x", "p") || a.Check("", "") {
		t.Error("Check")
	}
	if !(Auth{}).Check("anything", "at all") {
		t.Error("no credentials configured must let everything in")
	}
	enc := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	if !a.CheckProxyAuthorization(enc("u:p")) || a.CheckProxyAuthorization(enc("u:q")) ||
		a.CheckProxyAuthorization("") || a.CheckProxyAuthorization("Basic !!!notbase64") {
		t.Error("CheckProxyAuthorization")
	}
	if a.CheckProxyAuthorization(enc("u:p:x")) {
		t.Error("a longer password must not match")
	}
}

func TestListenAndServeReportsBusyPort(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	s := &Server{Dialer: direct{}, Listen: "127.0.0.1", Port: port}
	if err := s.ListenAndServe(context.Background()); err == nil {
		t.Error("a port in use was not reported")
	}
}
