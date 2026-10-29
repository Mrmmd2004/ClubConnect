package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Inbound is one "mixed" port: SOCKS5 (CONNECT + UDP ASSOCIATE) and HTTP proxy, told apart
// by the first byte. Optional username/password protects both.
type Inbound struct {
	m   *Manager
	cfg *Config
}

func (in *Inbound) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(in.cfg.Listen, strconv.Itoa(in.cfg.Port)))
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go in.handle(ctx, c)
	}
}

func (in *Inbound) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 16*1024)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 5 {
		in.socks(ctx, c, br)
	} else {
		in.http(ctx, c, br)
	}
}

func (in *Inbound) authOK(user, pass string) bool {
	if in.cfg.Username == "" {
		return true
	}
	u := subtle.ConstantTimeCompare([]byte(user), []byte(in.cfg.Username))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(in.cfg.Password))
	return u&p == 1
}

func splice(a net.Conn, ar io.Reader, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(b, ar)
	go cp(a, b)
	<-done
	select {
	case <-done:
	case <-time.After(2 * time.Minute): // the other direction lingers after a half-close
	}
	a.Close()
	b.Close()
}

// ---------------- SOCKS5 ----------------

func readAddr(br *bufio.Reader, atyp byte) (host string, raw []byte, err error) {
	switch atyp {
	case 1, 4:
		n := 4
		if atyp == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err = io.ReadFull(br, b); err != nil {
			return
		}
		return net.IP(b).String(), append([]byte{atyp}, b...), nil
	case 3:
		l, e := br.ReadByte()
		if e != nil {
			return "", nil, e
		}
		b := make([]byte, l)
		if _, err = io.ReadFull(br, b); err != nil {
			return
		}
		return string(b), append([]byte{3, l}, b...), nil
	}
	return "", nil, errors.New("bad address type")
}

func socksReply(c net.Conn, code byte, bind *net.UDPAddr) {
	r := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	if bind != nil {
		if ip4 := bind.IP.To4(); ip4 != nil {
			copy(r[4:8], ip4)
		}
		binary.BigEndian.PutUint16(r[8:10], uint16(bind.Port))
	}
	c.Write(r)
}

func (in *Inbound) socks(ctx context.Context, c net.Conn, br *bufio.Reader) {
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(0)
	if in.cfg.Username != "" {
		want = 2
	}
	has := false
	for _, m := range methods {
		if m == want {
			has = true
		}
	}
	if !has {
		c.Write([]byte{5, 0xFF})
		return
	}
	c.Write([]byte{5, want})
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
		if !in.authOK(string(u), string(p)) {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
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
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	switch rq[1] {
	case 1:
		dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		up, err := in.m.DialTCP(dctx, net.JoinHostPort(host, port))
		cancel()
		if err != nil {
			socksReply(c, 5, nil)
			return
		}
		socksReply(c, 0, nil)
		c.SetReadDeadline(zeroTime)
		splice(c, br, up)
	case 3:
		in.udpAssociate(ctx, c, br)
	default:
		socksReply(c, 7, nil)
	}
}

func (in *Inbound) udpAssociate(ctx context.Context, c net.Conn, br *bufio.Reader) {
	laddr, _ := c.LocalAddr().(*net.TCPAddr)
	raddr, _ := c.RemoteAddr().(*net.TCPAddr)
	if laddr == nil || raddr == nil {
		socksReply(c, 1, nil)
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: laddr.IP, Port: 0})
	if err != nil {
		socksReply(c, 1, nil)
		return
	}
	defer pc.Close()
	socksReply(c, 0, pc.LocalAddr().(*net.UDPAddr))
	c.SetReadDeadline(zeroTime)

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
			dest, raw, err := readAddr(rd, atyp)
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
				fc, err := in.m.DialUDP(dctx, net.JoinHostPort(dest, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
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

func (in *Inbound) http(ctx context.Context, c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if in.cfg.Username != "" {
		ok := false
		if a := strings.TrimPrefix(req.Header.Get("Proxy-Authorization"), "Basic "); a != "" {
			if raw, err := base64.StdEncoding.DecodeString(a); err == nil {
				u, p, _ := strings.Cut(string(raw), ":")
				ok = in.authOK(u, p)
			}
		}
		if !ok {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Club Connect\"\r\nContent-Length: 0\r\n\r\n"))
			return
		}
	}
	c.SetReadDeadline(zeroTime)
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
	up, err := in.m.DialTCP(dctx, target)
	cancel()
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if req.Method == http.MethodConnect {
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		splice(c, br, up)
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
	splice(c, br, up)
}

func init() { log.SetFlags(log.Ltime) }
