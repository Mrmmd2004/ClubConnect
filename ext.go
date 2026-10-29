package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// socks5Dial opens a TCP connection to addr through a local upstream SOCKS5 proxy (Psiphon, Tor).
func socks5Dial(ctx context.Context, upstream, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", upstream)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	b := make([]byte, 2)
	if _, err := io.ReadFull(c, b); err != nil || b[0] != 5 || b[1] != 0 {
		return fail(errors.New("upstream socks5 handshake failed"))
	}
	host, ps, err := net.SplitHostPort(addr)
	if err != nil {
		return fail(err)
	}
	p, _ := strconv.Atoi(ps)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(p>>8), byte(p))
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
	skip := 0
	switch h[3] {
	case 1:
		skip = 6
	case 4:
		skip = 18
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		return fail(err)
	}
	c.SetDeadline(zeroTime)
	return c, nil
}

var zeroTime time.Time
