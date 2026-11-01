package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// socksAddrBytes encodes ATYP + address + port the way SOCKS5 wants it. IP literals are sent
// as real addresses (v4 / v6) instead of as a "domain name" that happens to look like one.
func socksAddrBytes(host string, port int) []byte {
	var b []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			a := ip.As4()
			b = append([]byte{1}, a[:]...)
		} else {
			a := ip.As16()
			b = append([]byte{4}, a[:]...)
		}
	} else {
		if len(host) > 255 {
			host = host[:255]
		}
		b = append([]byte{3, byte(len(host))}, host...)
	}
	return append(b, byte(port>>8), byte(port))
}

// socks5Handshake opens a TCP connection to a local SOCKS5 server and negotiates "no auth".
func socks5Handshake(ctx context.Context, upstream string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 5 || b[1] != 0 {
		c.Close()
		return nil, errors.New("upstream socks5 handshake failed")
	}
	return c, nil
}

// readSocksReplyAddr reads the BND.ADDR / BND.PORT part of a reply whose first 4 bytes are h.
// ip is nil for a domain-name address.
func readSocksReplyAddr(c net.Conn, h []byte) (ip net.IP, port int, err error) {
	switch h[3] {
	case 1:
		r := make([]byte, 4)
		if _, err = io.ReadFull(c, r); err != nil {
			return
		}
		ip = net.IP(r)
	case 4:
		r := make([]byte, 16)
		if _, err = io.ReadFull(c, r); err != nil {
			return
		}
		ip = net.IP(r)
	case 3:
		l := make([]byte, 1)
		if _, err = io.ReadFull(c, l); err != nil {
			return
		}
		if _, err = io.CopyN(io.Discard, c, int64(l[0])); err != nil {
			return
		}
	default:
		err = errors.New("upstream sent an unknown address type")
		return
	}
	pb := make([]byte, 2)
	if _, err = io.ReadFull(c, pb); err != nil {
		return
	}
	port = int(pb[0])<<8 | int(pb[1])
	return
}

// socks5Dial opens a TCP connection to addr through a local upstream SOCKS5 proxy
// (Psiphon, Tor, Aether).
func socks5Dial(ctx context.Context, upstream, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	c, err := socks5Handshake(ctx, upstream)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	req := append([]byte{5, 1, 0}, socksAddrBytes(host, p)...)
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return fail(err)
	}
	if h[1] != 0 {
		return fail(errors.New("upstream refused connection"))
	}
	if _, _, err := readSocksReplyAddr(c, h); err != nil {
		return fail(err)
	}
	c.SetDeadline(zeroTime)
	return c, nil
}

var zeroTime time.Time

// ---------- SOCKS5 UDP ASSOCIATE client (used for Aether, whose tunnels all carry UDP) ----------

var udpBufPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

type udpAssoc struct {
	tc  net.Conn // the control connection: the association lives as long as it does
	uc  *net.UDPConn
	hdr []byte
}

func (c *udpAssoc) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(c.hdr)+len(p))
	buf = append(buf, c.hdr...)
	buf = append(buf, p...)
	if _, err := c.uc.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpAssoc) Read(p []byte) (int, error) {
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp
	for {
		n, err := c.uc.Read(buf)
		if err != nil {
			return 0, err
		}
		if n < 10 || buf[2] != 0 {
			continue // too short, or a fragment (not supported)
		}
		off := 4
		switch buf[3] {
		case 1:
			off += 4
		case 4:
			off += 16
		case 3:
			off += 1 + int(buf[4])
		default:
			continue
		}
		off += 2
		if off > n {
			continue
		}
		return copy(p, buf[off:n]), nil
	}
}

func (c *udpAssoc) Close() error {
	c.uc.Close()
	return c.tc.Close()
}
func (c *udpAssoc) LocalAddr() net.Addr                { return c.uc.LocalAddr() }
func (c *udpAssoc) RemoteAddr() net.Addr               { return c.uc.RemoteAddr() }
func (c *udpAssoc) SetDeadline(t time.Time) error      { return c.uc.SetDeadline(t) }
func (c *udpAssoc) SetReadDeadline(t time.Time) error  { return c.uc.SetReadDeadline(t) }
func (c *udpAssoc) SetWriteDeadline(t time.Time) error { return c.uc.SetWriteDeadline(t) }

// socks5UDPDial returns a connected-datagram net.Conn to addr through the upstream's UDP relay.
func socks5UDPDial(ctx context.Context, upstream, addr string) (net.Conn, error) {
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil {
		return nil, err
	}
	tc, err := socks5Handshake(ctx, upstream)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { tc.Close(); return nil, e }
	if _, err := tc.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(tc, h); err != nil {
		return fail(err)
	}
	if h[1] != 0 {
		return fail(errors.New("upstream refused UDP associate"))
	}
	relayIP, relayPort, err := readSocksReplyAddr(tc, h)
	if err != nil {
		return fail(err)
	}
	if relayIP == nil || relayIP.IsUnspecified() {
		uh, _, _ := net.SplitHostPort(upstream)
		relayIP = net.ParseIP(uh)
	}
	if relayIP == nil {
		return fail(errors.New("upstream sent no usable UDP relay address"))
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: relayPort})
	if err != nil {
		return fail(err)
	}
	tc.SetDeadline(zeroTime)
	c := &udpAssoc{tc: tc, uc: uc, hdr: append([]byte{0, 0, 0}, socksAddrBytes(host, port)...)}
	go func() {
		io.Copy(io.Discard, tc) // returns when the relay (or we) close the control connection
		uc.Close()
	}()
	return c, nil
}
