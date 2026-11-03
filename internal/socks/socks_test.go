package socks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestAddrBytes(t *testing.T) {
	if got, want := AddrBytes("1.2.3.4", 443), []byte{1, 1, 2, 3, 4, 0x01, 0xbb}; !bytes.Equal(got, want) {
		t.Errorf("ipv4: % x, want % x", got, want)
	}
	d := AddrBytes("example.com", 80)
	if d[0] != 3 || d[1] != 11 || string(d[2:13]) != "example.com" || d[13] != 0 || d[14] != 80 {
		t.Errorf("domain: % x", d)
	}
	v6 := AddrBytes("2606:4700::1111", 53)
	if len(v6) != 19 || v6[0] != 4 {
		t.Errorf("ipv6: % x", v6)
	}
	// an IPv4-mapped literal is sent as a real IPv4 address
	if m := AddrBytes("::ffff:1.2.3.4", 1); m[0] != 1 || len(m) != 7 {
		t.Errorf("mapped: % x", m)
	}
	// over-long names are cut to 255 bytes
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	if l := AddrBytes(string(long), 1); l[1] != 255 || len(l) != 2+255+2 {
		t.Errorf("long host: len %d, n %d", len(l), l[1])
	}
}

func TestAddrRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{{"1.2.3.4", 80}, {"2606:4700::1111", 443}, {"example.com", 8888}} {
		enc := AddrBytes(tc.host, tc.port)
		br := bufio.NewReader(bytes.NewReader(enc[1:]))
		host, raw, err := ReadAddr(br, enc[0])
		if err != nil {
			t.Fatalf("%s: %v", tc.host, err)
		}
		if host != tc.host {
			t.Errorf("host %q, want %q", host, tc.host)
		}
		if !bytes.Equal(raw, enc[:len(enc)-2]) {
			t.Errorf("raw % x, want % x", raw, enc[:len(enc)-2])
		}
		pb := make([]byte, 2)
		io.ReadFull(br, pb)
		if int(binary.BigEndian.Uint16(pb)) != tc.port {
			t.Errorf("port % x, want %d", pb, tc.port)
		}
	}
}

func TestReadAddrErrors(t *testing.T) {
	if _, _, err := ReadAddr(bufio.NewReader(bytes.NewReader(nil)), 9); !errors.Is(err, ErrBadAddrType) {
		t.Errorf("bad atyp: %v", err)
	}
	if _, _, err := ReadAddr(bufio.NewReader(bytes.NewReader([]byte{1, 2})), AtypIPv4); err == nil {
		t.Error("short IPv4 accepted")
	}
	if _, _, err := ReadAddr(bufio.NewReader(bytes.NewReader([]byte{5, 'a'})), AtypDomain); err == nil {
		t.Error("short domain accepted")
	}
}

func TestReadReplyAddr(t *testing.T) {
	ip, port, err := ReadReplyAddr(bytes.NewReader([]byte{10, 0, 0, 1, 0x1f, 0x90}), AtypIPv4)
	if err != nil || ip.String() != "10.0.0.1" || port != 8080 {
		t.Errorf("ipv4 reply: %v %d %v", ip, port, err)
	}
	ip, port, err = ReadReplyAddr(bytes.NewReader([]byte{3, 'a', 'b', 'c', 0, 80}), AtypDomain)
	if err != nil || ip != nil || port != 80 {
		t.Errorf("domain reply: %v %d %v", ip, port, err)
	}
	if _, _, err = ReadReplyAddr(bytes.NewReader(nil), 7); !errors.Is(err, ErrUnknownAtyp) {
		t.Errorf("unknown atyp: %v", err)
	}
}

func TestUDPPayloadOffset(t *testing.T) {
	pkt := append([]byte{0, 0, 0}, AddrBytes("1.2.3.4", 53)...)
	pkt = append(pkt, []byte("payload")...)
	off, ok := UDPPayloadOffset(pkt)
	if !ok || string(pkt[off:]) != "payload" {
		t.Errorf("ipv4 datagram: %d %v", off, ok)
	}
	dom := append([]byte{0, 0, 0}, AddrBytes("example.com", 53)...)
	dom = append(dom, []byte("x")...)
	if off, ok := UDPPayloadOffset(dom); !ok || string(dom[off:]) != "x" {
		t.Errorf("domain datagram: %d %v", off, ok)
	}
	frag := append([]byte(nil), pkt...)
	frag[2] = 1
	if _, ok := UDPPayloadOffset(frag); ok {
		t.Error("fragment accepted")
	}
	if _, ok := UDPPayloadOffset([]byte{0, 0, 0, 1, 1}); ok {
		t.Error("short datagram accepted")
	}
	bad := append([]byte(nil), pkt...)
	bad[3] = 9
	if _, ok := UDPPayloadOffset(bad); ok {
		t.Error("unknown atyp accepted")
	}
}

// fakeUpstream is a tiny SOCKS5 server: it accepts CONNECT (and answers rep) and then echoes.
func fakeUpstream(t *testing.T, rep byte, bind string) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				h := make([]byte, 2)
				io.ReadFull(br, h)
				io.CopyN(io.Discard, br, int64(h[1]))
				c.Write([]byte{5, 0})
				rq := make([]byte, 4)
				io.ReadFull(br, rq)
				_, _, _ = ReadAddr(br, rq[3])
				io.CopyN(io.Discard, br, 2)
				reply := []byte{5, rep, 0}
				reply = append(reply, AddrBytes(bind, 1080)...)
				c.Write(reply)
				if rep == 0 {
					io.Copy(c, br)
				}
			}()
		}
	}()
	return l.Addr().String()
}

func TestDialThroughUpstream(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "::1", "bound.example"} {
		up := fakeUpstream(t, 0, bind)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := Dial(ctx, up, "example.com:443")
		cancel()
		if err != nil {
			t.Fatalf("bind %s: %v", bind, err)
		}
		c.Write([]byte("ping"))
		b := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
			t.Errorf("bind %s echo: %q %v", bind, b, err)
		}
		c.Close()
	}
}

func TestDialRefused(t *testing.T) {
	up := fakeUpstream(t, 5, "0.0.0.0")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, up, "example.com:443"); !errors.Is(err, ErrRefused) {
		t.Errorf("want ErrRefused, got %v", err)
	}
}

func TestDialBadAddress(t *testing.T) {
	if _, err := Dial(context.Background(), "127.0.0.1:1", "no-port"); err == nil {
		t.Error("address without port accepted")
	}
	if _, err := Dial(context.Background(), "127.0.0.1:1", "host:notaport"); err == nil {
		t.Error("non-numeric port accepted")
	}
}

func TestHandshakeRejectsNonSocks(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("HT"))
		c.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := Handshake(ctx, l.Addr().String()); !errors.Is(err, ErrHandshake) {
		t.Errorf("want ErrHandshake, got %v", err)
	}
}

func TestServeGate(t *testing.T) {
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	var dialed string
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		dialed = addr
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}
	gate, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeGate(ctx, gate, dial)

	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	c, err := Dial(dctx, gate.Addr().String(), "some.host:"+strconv.Itoa(443))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "hello" {
		t.Errorf("gate echo: %q %v", b, err)
	}
	if dialed != "some.host:443" {
		t.Errorf("gate dialed %q", dialed)
	}
}

func TestServeGateRejectsUDPAssociate(t *testing.T) {
	gate, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ServeGate(ctx, gate, func(context.Context, string) (net.Conn, error) { return nil, errors.New("no") })
	c, _ := net.Dial("tcp", gate.Addr().String())
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write(append([]byte{5, CmdUDPAssociate, 0}, AddrBytes("0.0.0.0", 0)...))
	r := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, r); err != nil || r[1] != RepCmdNotSupported {
		t.Errorf("reply % x err %v", r, err)
	}
}

// fakeUDPRelay answers UDP ASSOCIATE and then echoes every datagram back, prefixed by the
// address header it received (which is what a real relay does for the return path).
func TestUDPDial(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			relay.WriteToUDP(buf[:n], from) // header + payload unchanged: the client strips the header
		}
	}()
	ctl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ctl.Close()
	go func() {
		for {
			c, err := ctl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				h := make([]byte, 2)
				io.ReadFull(br, h)
				io.CopyN(io.Discard, br, int64(h[1]))
				c.Write([]byte{5, 0})
				io.CopyN(io.Discard, br, 10) // the UDP ASSOCIATE request
				rp := relay.LocalAddr().(*net.UDPAddr)
				c.Write(append([]byte{5, 0, 0}, AddrBytes("0.0.0.0", rp.Port)...))
				io.Copy(io.Discard, br)
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := UDPDial(ctx, ctl.Addr().String(), "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("query")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "query" {
		t.Errorf("udp echo: %q %v", b[:n], err)
	}
}
