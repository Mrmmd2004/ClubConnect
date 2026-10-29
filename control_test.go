package main

import (
	"strings"
	"testing"
)

func TestNormMode(t *testing.T) {
	cases := map[string]string{
		"Auto":           "auto",
		"warp+psiphon":   "warp+psiphon",
		"Cloudflare-Tor": "warp+tor",
		"cf->psiphon":    "warp+psiphon",
		"WARP":           "warp",
		"":               "",
		"nonsense":       "",
	}
	for in, want := range cases {
		if got := normMode(in); got != want {
			t.Errorf("normMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPsiphonProtocols(t *testing.T) {
	// a chained Psiphon must never be offered a UDP protocol
	for _, p := range []int{0, 1, 2} {
		for _, style := range []string{"auto", "cdn", "direct"} {
			for _, n := range psiphonProtocols(p, style, true) {
				if strings.Contains(n, "QUIC") {
					t.Errorf("chained level %d style %s offers %s", p, style, n)
				}
			}
			if len(psiphonProtocols(p, style, true)) == 0 {
				t.Errorf("chained level %d style %s has no protocols", p, style)
			}
		}
	}
	if psiphonProtocols(2, "auto", false) != nil {
		t.Error("level 2 must not limit protocols")
	}
	for _, n := range psiphonProtocols(1, "auto", false) {
		if strings.Contains(n, "CDN") {
			t.Errorf("level 1 must not name %s (stock tunnel-core rejects it)", n)
		}
	}
	for _, n := range psiphonProtocols(0, "cdn", false) {
		if !strings.Contains(n, "CDN") {
			t.Errorf("cdn style offers %s", n)
		}
	}
}

func TestConfigDefaultsStartNothing(t *testing.T) {
	c := defaultConfig()
	c.DataDir = t.TempDir()
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if c.Mode != "" {
		t.Errorf("default mode must be empty (no auto start), got %q", c.Mode)
	}
	c.Mode = "Cloudflare-Psiphon"
	if err := c.validate(); err != nil || c.Mode != "warp+psiphon" {
		t.Errorf("mode not normalised: %q %v", c.Mode, err)
	}
	c.Tor.Bridge = "bogus"
	if err := c.validate(); err == nil {
		t.Error("bogus tor.bridge accepted")
	}
}
