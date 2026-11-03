package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

// Splice copies both ways between a (whose already-buffered input is ar) and b until both
// directions are done, then closes both. A half-closed direction may linger at most two minutes.
func Splice(a net.Conn, ar io.Reader, b net.Conn) {
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

// DialFunc opens an outgoing TCP connection.
type DialFunc func(ctx context.Context, addr string) (net.Conn, error)

// ServeGate runs a minimal SOCKS5 server (CONNECT only, no auth) on ln until ctx ends; every
// connection is opened with dial. It is how an in-process tunnel is handed to a helper program
// that only knows how to use a SOCKS5 proxy.
func ServeGate(ctx context.Context, ln net.Listener, dial DialFunc) {
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
		go gateConn(ctx, c, dial)
	}
}

func gateConn(ctx context.Context, c net.Conn, dial DialFunc) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil || h[0] != Version5 {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(h[1])); err != nil {
		return
	}
	c.Write([]byte{Version5, 0})
	rq := make([]byte, 4)
	if _, err := io.ReadFull(br, rq); err != nil || rq[0] != Version5 {
		return
	}
	host, _, err := ReadAddr(br, rq[3])
	if err != nil {
		Reply(c, RepAddrNotSupported, nil)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	if rq[1] != CmdConnect {
		Reply(c, RepCmdNotSupported, nil)
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	up, err := dial(dctx, net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		Reply(c, RepConnRefused, nil)
		return
	}
	Reply(c, RepSuccess, nil)
	c.SetReadDeadline(time.Time{})
	Splice(c, br, up)
}
