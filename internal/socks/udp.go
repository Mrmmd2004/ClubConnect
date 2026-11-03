package socks

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE client (used for Aether, whose tunnels all carry UDP).

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
		off, ok := UDPPayloadOffset(buf[:n])
		if !ok {
			continue // too short, a fragment (not supported), or a bad address type
		}
		return copy(p, buf[off:n]), nil
	}
}

// UDPPayloadOffset returns where the payload starts inside a SOCKS5 UDP datagram, or false when
// the datagram is too short, fragmented or carries an unknown address type.
func UDPPayloadOffset(buf []byte) (int, bool) {
	n := len(buf)
	if n < 10 || buf[2] != 0 {
		return 0, false
	}
	off := 4
	switch buf[3] {
	case AtypIPv4:
		off += 4
	case AtypIPv6:
		off += 16
	case AtypDomain:
		off += 1 + int(buf[4])
	default:
		return 0, false
	}
	off += 2
	if off > n {
		return 0, false
	}
	return off, true
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

// UDPDial returns a connected-datagram net.Conn to addr through the upstream's UDP relay.
func UDPDial(ctx context.Context, upstream, addr string) (net.Conn, error) {
	host, port, err := SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	tc, err := Handshake(ctx, upstream)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { tc.Close(); return nil, e }
	if _, err := tc.Write([]byte{Version5, CmdUDPAssociate, 0, AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(tc, h); err != nil {
		return fail(err)
	}
	if h[1] != RepSuccess {
		return fail(ErrUDPRefused)
	}
	relayIP, relayPort, err := ReadReplyAddr(tc, h[3])
	if err != nil {
		return fail(err)
	}
	if relayIP == nil || relayIP.IsUnspecified() {
		uh, _, _ := net.SplitHostPort(upstream)
		relayIP = net.ParseIP(uh)
	}
	if relayIP == nil {
		return fail(ErrNoRelay)
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: relayPort})
	if err != nil {
		return fail(err)
	}
	tc.SetDeadline(time.Time{})
	c := &udpAssoc{tc: tc, uc: uc, hdr: append([]byte{0, 0, 0}, AddrBytes(host, port)...)}
	go func() {
		io.Copy(io.Discard, tc) // returns when the relay (or we) close the control connection
		uc.Close()
	}()
	return c, nil
}
