// Package inbound is the proxy port Club Connect offers to the applications: one "mixed" port
// that speaks SOCKS5 (CONNECT and UDP ASSOCIATE) and HTTP proxy, told apart by the first byte.
package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"clubconnect/internal/socks"
)

// Dialer opens the outgoing connections (the core.Manager implements it).
type Dialer interface {
	DialTCP(ctx context.Context, addr string) (net.Conn, error)
	DialUDP(ctx context.Context, addr string) (net.Conn, error)
}

// Server is one mixed proxy port. Optional username/password protects both protocols.
type Server struct {
	Dialer Dialer
	Auth   Auth
	Listen string // address to bind, e.g. "127.0.0.1"
	Port   int

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// ListenAndServe binds Listen:Port and serves until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.Listen, strconv.Itoa(s.Port)))
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve accepts on an already-bound listener until ctx ends. When it ends, the connections that
// are still open are closed too, so stopping a mode really cuts everything that went through it.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close(); s.closeAll() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.track(c) { // the server is shutting down
			c.Close()
			continue
		}
		go func() {
			defer s.untrack(c)
			s.handle(ctx, c)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) closeAll() {
	s.mu.Lock()
	s.closed = true // nothing new is tracked from now on
	open := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		open = append(open, c)
	}
	s.mu.Unlock()
	for _, c := range open {
		c.Close()
	}
}

// Open reports how many client connections are open right now.
func (s *Server) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 16*1024)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == socks.Version5 {
		s.socks(ctx, c, br)
	} else {
		s.http(ctx, c, br)
	}
}

// ---------------- SOCKS5 ----------------

func (s *Server) socks(ctx context.Context, c net.Conn, br *bufio.Reader) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(0)
	if s.Auth.Enabled() {
		want = 2
	}
	has := false
	for _, m := range methods {
		if m == want {
			has = true
		}
	}
	if !has {
		c.Write([]byte{socks.Version5, 0xFF})
		return
	}
	c.Write([]byte{socks.Version5, want})
	if want == 2 {
		v, _ := br.ReadByte()
		ul, _ := br.ReadByte()
		u := make([]byte, ul)
		io.ReadFull(br, u)
		pl, _ := br.ReadByte()
		p := make([]byte, pl)
		if _, err := io.ReadFull(br, p); err != nil || v != 1 {
			return
		}
		if !s.Auth.Check(string(u), string(p)) {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	rq := make([]byte, 4)
	if _, err := io.ReadFull(br, rq); err != nil || rq[0] != socks.Version5 {
		return
	}
	host, _, err := socks.ReadAddr(br, rq[3])
	if err != nil {
		socks.Reply(c, socks.RepAddrNotSupported, nil)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	switch rq[1] {
	case socks.CmdConnect:
		dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		up, err := s.Dialer.DialTCP(dctx, net.JoinHostPort(host, port))
		cancel()
		if err != nil {
			socks.Reply(c, socks.RepConnRefused, nil)
			return
		}
		socks.Reply(c, socks.RepSuccess, nil)
		c.SetReadDeadline(time.Time{})
		socks.Splice(c, br, up)
	case socks.CmdUDPAssociate:
		s.udpAssociate(ctx, c, br)
	default:
		socks.Reply(c, socks.RepCmdNotSupported, nil)
	}
}

func (s *Server) udpAssociate(ctx context.Context, c net.Conn, br *bufio.Reader) {
	laddr, _ := c.LocalAddr().(*net.TCPAddr)
	raddr, _ := c.RemoteAddr().(*net.TCPAddr)
	if laddr == nil || raddr == nil {
		socks.Reply(c, socks.RepGeneralFailure, nil)
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: laddr.IP, Port: 0})
	if err != nil {
		socks.Reply(c, socks.RepGeneralFailure, nil)
		return
	}
	defer pc.Close()
	socks.Reply(c, socks.RepSuccess, pc.LocalAddr().(*net.UDPAddr))
	c.SetReadDeadline(time.Time{})

	type flow struct {
		conn net.Conn
		hdr  []byte // ATYP+ADDR+PORT exactly as the client wrote it
	}
	var mu sync.Mutex
	flows := map[string]*flow{}
	var client atomic.Pointer[net.UDPAddr]
	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.conn.Close()
		}
		mu.Unlock()
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.Equal(raddr.IP) || n < 10 || buf[2] != 0 { // wrong sender, short, or fragmented
				continue
			}
			client.Store(from)
			rd := bufio.NewReader(bytes.NewReader(buf[3:n]))
			atyp, _ := rd.ReadByte()
			dest, raw, err := socks.ReadAddr(rd, atyp)
			if err != nil {
				continue
			}
			pb := make([]byte, 2)
			if _, err := io.ReadFull(rd, pb); err != nil {
				continue
			}
			payload, _ := io.ReadAll(rd)
			hdr := append(raw, pb...)
			key := string(hdr)
			mu.Lock()
			f := flows[key]
			if f == nil && len(flows) < 256 {
				dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
				fc, err := s.Dialer.DialUDP(dctx, net.JoinHostPort(dest, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
				cancel()
				if err == nil {
					f = &flow{conn: fc, hdr: hdr}
					flows[key] = f
					go func(f *flow) {
						rb := make([]byte, 65535)
						for {
							f.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
							n, err := f.conn.Read(rb)
							if err != nil {
								f.conn.Close()
								mu.Lock()
								delete(flows, key)
								mu.Unlock()
								return
							}
							if to := client.Load(); to != nil {
								out := append([]byte{0, 0, 0}, f.hdr...)
								pc.WriteToUDP(append(out, rb[:n]...), to)
							}
						}
					}(f)
				}
			}
			mu.Unlock()
			if f != nil {
				f.conn.Write(payload)
			}
		}
	}()
	io.Copy(io.Discard, br) // the association lives as long as the control connection
}

// ---------------- HTTP proxy ----------------

func (s *Server) http(ctx context.Context, c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if s.Auth.Enabled() && !s.Auth.CheckProxyAuthorization(req.Header.Get("Proxy-Authorization")) {
		c.Write(proxyAuthRequired)
		return
	}
	c.SetReadDeadline(time.Time{})
	target := req.Host
	if req.Method != http.MethodConnect && req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		if req.Method == http.MethodConnect {
			target = net.JoinHostPort(target, "443")
		} else {
			target = net.JoinHostPort(strings.Trim(target, "[]"), "80")
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	up, err := s.Dialer.DialTCP(dctx, target)
	cancel()
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if req.Method == http.MethodConnect {
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		socks.Splice(c, br, up)
		return
	}
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		up.Close()
		return
	}
	socks.Splice(c, br, up)
}
