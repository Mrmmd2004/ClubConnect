package backends

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"clubconnect/internal/config"
	"clubconnect/internal/proc"
)

// Some networks (Iran's, notably) reset a TLS ClientHello whose SNI ends in cloudflareclient.com,
// which makes the free-device registration fail and, with it, the whole WARP mode. Splitting the
// ClientHello into small pieces gets past that kind of filter, exactly like Aether's --fragment.

// fragConn splits the first Write (the ClientHello) into 8-16 byte pieces with short pauses.
type fragConn struct {
	net.Conn
	done bool
}

func (c *fragConn) Write(p []byte) (int, error) {
	if c.done {
		return c.Conn.Write(p)
	}
	c.done = true
	total := 0
	for len(p) > 0 {
		n := 8 + rand.Intn(9)
		if n > len(p) {
			n = len(p)
		}
		w, err := c.Conn.Write(p[:n])
		total += w
		if err != nil {
			return total, err
		}
		p = p[n:]
		if len(p) > 0 {
			time.Sleep(time.Duration(2+rand.Intn(9)) * time.Millisecond)
		}
	}
	return total, nil
}

// fragDialTLS is an http.Transport.DialTLSContext that fragments the ClientHello.
func fragDialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	c := tls.Client(&fragConn{Conn: raw}, &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// importAetherIdentity lets Aether register the free device (it has more ways around a filtered
// API than we do) and reads the WireGuard identity it saved.
func importAetherIdentity(ctx context.Context, cfg *config.Config) (*warpIdentity, error) {
	bin := AetherBin(cfg)
	if bin == "" {
		return nil, errors.New("aether not found")
	}
	if err := os.MkdirAll(aetherDir(cfg), 0o700); err != nil {
		return nil, err
	}
	args := append([]string{"--register", "wg"}, aetherIdentityFlags(cfg)...)
	if cfg.Aether.Fragment {
		args = append(args, "--fragment")
	}
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	proc.HideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 300 {
			tail = tail[len(tail)-300:]
		}
		return nil, fmt.Errorf("aether --register wg failed: %v: %s", err, tail)
	}
	return readAetherIdentity(filepath.Join(aetherDir(cfg), "aether.toml"))
}

// readAetherIdentity reads the four WireGuard values from Aether's identity file (a flat TOML).
func readAetherIdentity(path string) (*warpIdentity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	id := &warpIdentity{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), "\"'")
		switch k {
		case "wg_private_key":
			id.PrivateKey = v
		case "wg_peer_public_key":
			id.PeerPublic = v
		case "ipv4":
			id.V4 = v
		case "ipv6":
			id.V6 = v
		}
	}
	if id.PrivateKey == "" || id.PeerPublic == "" || id.V4 == "" {
		return nil, errors.New("aether identity file is incomplete")
	}
	wlog.Infof("using the WireGuard identity Aether registered")
	return id, nil
}
