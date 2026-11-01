package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormMode(t *testing.T) {
	cases := map[string]string{
		"Auto":           "auto",
		"warp+psiphon":   "warp+psiphon",
		"Cloudflare-Tor": "warp+tor",
		"WARP-Tor":       "warp+tor",
		"warp->psiphon":  "warp+psiphon",
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

func TestSplitModeAndVariant(t *testing.T) {
	m, v := splitMode("warp+tor@masque-h2")
	if normMode(m) != "warp+tor" || normVariant(v) != "masque-h2" {
		t.Errorf("splitMode gave %q %q", m, v)
	}
	if m, v := splitMode("auto"); m != "auto" || v != "" {
		t.Errorf("splitMode without variant gave %q %q", m, v)
	}
	cases := map[string]string{
		"MASQUE":           "masque",
		"h3":               "masque",
		"h2":               "masque-h2",
		"wireguard":        "wg",
		"warp-in-warp":     "gool-classic",
		"masque in masque": "mim",
		"gool":             "gool",
		"auto":             "auto",
		"wg+noize":         "wg-noize",
		"":                 "",
		"nonsense":         "",
	}
	for in, want := range cases {
		if got := normVariant(in); got != want {
			t.Errorf("normVariant(%q) = %q, want %q", in, got, want)
		}
	}
	for _, v := range warpVariants {
		if normVariant(v) != v {
			t.Errorf("variant %q does not survive normVariant", v)
		}
		if variantLabels[v] == "" || variantShort[v] == "" {
			t.Errorf("variant %q has no label", v)
		}
	}
}

func TestVariantSettingsPerMode(t *testing.T) {
	c := defaultConfig()
	c.setVariant("warp+tor", "gool")
	c.setVariant("warp", "masque")
	if c.variantFor("warp+tor") != "gool" || c.variantFor("warp") != "masque" {
		t.Error("variant not stored per mode")
	}
	if c.variantFor("warp+psiphon") != "auto" {
		t.Error("an unset mode must default to auto")
	}
}

func TestAutoWavesWithoutAether(t *testing.T) {
	c := defaultConfig()
	c.DataDir = t.TempDir()
	a := NewAutoWarp(c)
	if aetherBin(c) != "" {
		t.Skip("an aether program is installed here")
	}
	waves := a.waves()
	if len(waves) == 0 {
		t.Fatal("no wave left: the built-in WireGuard must always be tried")
	}
	for _, w := range waves {
		for _, v := range w {
			if variantNeedsAether(v) {
				t.Errorf("variant %s needs aether but aether is missing", v)
			}
		}
	}
}

func TestSocksAddrBytes(t *testing.T) {
	if got, want := socksAddrBytes("1.2.3.4", 443), []byte{1, 1, 2, 3, 4, 0x01, 0xbb}; !bytes.Equal(got, want) {
		t.Errorf("ipv4: % x, want % x", got, want)
	}
	d := socksAddrBytes("example.com", 80)
	if d[0] != 3 || d[1] != 11 || string(d[2:13]) != "example.com" || d[13] != 0 || d[14] != 80 {
		t.Errorf("domain: % x", d)
	}
	v6 := socksAddrBytes("2606:4700::1111", 53)
	if len(v6) != 19 || v6[0] != 4 {
		t.Errorf("ipv6: % x", v6)
	}
}

func TestConfigVariantValidation(t *testing.T) {
	c := defaultConfig()
	c.DataDir = t.TempDir()
	c.Mode = "warp@masque-h2"
	if err := c.validate(); err != nil || c.Mode != "warp" || c.ModeVariant != "masque-h2" {
		t.Errorf("mode@variant not understood: %q %q %v", c.Mode, c.ModeVariant, err)
	}
	c.Warp.TorVariant = "bogus"
	if err := c.validate(); err == nil {
		t.Error("bogus warp.tor_variant accepted")
	}
}
