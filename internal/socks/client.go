package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Errors of the client side. Their texts are shown in logs, so they stay as they were.
var (
	ErrHandshake   = errors.New("upstream socks5 handshake failed")
	ErrRefused     = errors.New("upstream refused connection")
	ErrUDPRefused  = errors.New("upstream refused UDP associate")
	ErrNoRelay     = errors.New("upstream sent no usable UDP relay address")
	ErrUnknownAtyp = errors.New("upstream sent an unknown address type")
)

// Handshake opens a TCP connection to a local SOCKS5 server and negotiates "no auth". The
// context deadline (if any) becomes the connection deadline until the caller clears it.
func Handshake(ctx context.Context, upstream string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write([]byte{Version5, 1, 0}); err != nil {
		c.Close()
		return nil, err
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != Version5 || b[1] != 0 {
		c.Close()
		return nil, ErrHandshake
	}
	return c, nil
}

// Dial opens a TCP connection to addr through a local upstream SOCKS5 proxy (Psiphon, Tor,
// Aether).
func Dial(ctx context.Context, upstream, addr string) (net.Conn, error) {
	host, p, err := SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	c, err := Handshake(ctx, upstream)
	if err != nil {
		return nil, err
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	req := append([]byte{Version5, CmdConnect, 0}, AddrBytes(host, p)...)
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return fail(err)
	}
	if h[1] != RepSuccess {
		return fail(ErrRefused)
	}
	if _, _, err := ReadReplyAddr(c, h[3]); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}
