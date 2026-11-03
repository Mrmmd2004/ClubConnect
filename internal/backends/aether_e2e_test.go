package backends

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestFakeAetherHelper is not a test: it is the stand-in for the aether program. It answers the
// way the real one does - a SOCKS5 port that carries an HTTP exchange - so the whole path
// (start, supervise, probe, ready, dial, stop) can be tested without the real program.
func TestFakeAetherHelper(t *testing.T) {
	if os.Getenv("CC_FAKE_AETHER") != "1" {
		return
	}
	var bind string
	for i, a := range os.Args {
		if a == "--bind" && i+1 < len(os.Args) {
			bind = os.Args[i+1]
		}
	}
	if f := os.Getenv("CC_ARGS_FILE"); f != "" {
		os.WriteFile(f, []byte(strings.Join(os.Args, "\n")), 0o600)
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		os.Exit(2)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			os.Exit(0)
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
			switch rq[3] {
			case 1:
				io.CopyN(io.Discard, br, 4)
			case 4:
				io.CopyN(io.Discard, br, 16)
			case 3:
				l, _ := br.ReadByte()
				io.CopyN(io.Discard, br, int64(l))
			}
			io.CopyN(io.Discard, br, 2)
			c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			c.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
		}()
	}
}

func fakeAetherScript(t *testing.T) string {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "aether")
	script := "#!/bin/sh\nexec \"" + exe + "\" -test.run=TestFakeAetherHelper -- \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAetherWarpEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	argsFile := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("CC_FAKE_AETHER", "1")
	t.Setenv("CC_ARGS_FILE", argsFile)
	c := testCfg(t)
	c.Aether.Bin = fakeAetherScript(t)
	a := NewAetherWarp(c, "masque-h2")
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !a.Ready() {
		if time.Now().After(deadline) {
			t.Fatalf("aether never became ready (last error %q)", a.LastError())
		}
		time.Sleep(50 * time.Millisecond)
	}
	port := a.port.Load()
	if port < 8801 || port > 8899 {
		t.Errorf("aether got port %d, outside the preferred 88xx range", port)
	}

	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := a.DialTCP(dctx, "example.com:80")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	buf := make([]byte, 12)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "HTTP/1.1 204" {
		t.Errorf("through the tunnel: %q %v", buf, err)
	}
	conn.Close()

	b, _ := os.ReadFile(argsFile)
	args := string(b)
	for _, want := range []string{"--masque", "--h2", "--bind", "--quick-reconnect"} {
		if !strings.Contains(args, want) {
			t.Errorf("aether was started without %s:\n%s", want, args)
		}
	}
	if !strings.Contains(args, "aether.toml") {
		t.Error("the identity file is not in the data directory")
	}

	t0 := time.Now()
	a.Stop()
	if a.Ready() {
		t.Error("ready after Stop")
	}
	if time.Since(t0) > 6*time.Second {
		t.Errorf("Stop took %s", time.Since(t0))
	}
	if a.port.Load() != 0 {
		t.Error("the port was not released")
	}
	if _, err := a.DialTCP(context.Background(), "example.com:80"); err == nil {
		t.Error("dialling a stopped engine worked")
	}
	time.Sleep(300 * time.Millisecond)
	if cn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(int(port))), time.Second); err == nil {
		cn.Close()
		t.Error("the aether process is still listening after Stop")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
