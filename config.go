package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Everything is optional: with no config file Club Connect runs with sane defaults.
type Config struct {
	Listen         string   `json:"listen"`
	Port           int      `json:"port"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	APIPort        int      `json:"api_port"` // default 8808, -1 = off
	APIToken       string   `json:"api_token"`
	DataDir        string   `json:"data_dir"`
	Mode           string   `json:"mode"`  // mode to start at launch; empty = start nothing (menu / API decides)
	Order          []string `json:"order"` // backends used by the "auto" mode, priority order
	HealthURLs     []string `json:"health_urls"`
	HealthInterval int      `json:"health_interval_sec"`
	Verbose        bool     `json:"verbose"`

	// Not read from config.json: the mode used last time (kept in settings.json).
	LastMode string `json:"-"`
	// Set when "mode" was written as "warp@masque" (or by -variant): used for that start only.
	ModeVariant string `json:"-"`

	Warp struct {
		Endpoints      []string `json:"endpoints"`
		WGConf         string   `json:"wg_conf"`
		Variant        string   `json:"variant"`         // WARP mode: auto | wg | masque | masque-h2 | gool | gool-classic | mim | wg-noize
		PsiphonVariant string   `json:"psiphon_variant"` // which WARP the WARP -> Psiphon mode uses
		TorVariant     string   `json:"tor_variant"`     // which WARP the WARP -> Tor mode uses
		Auto           []string `json:"auto"`            // waves for variant auto, e.g. ["wg+masque","gool"]
	} `json:"warp"`
	Aether struct {
		Bin      string `json:"bin"`
		Scan     string `json:"scan"`     // turbo | balanced | thorough | verified | ironclad
		IP       string `json:"ip"`       // 4 | 6 | both
		Noize    string `json:"noize"`    // "" (aether's default) | off | light | firewall | balanced | gfw | aggressive
		Fragment bool   `json:"fragment"` // split the TLS ClientHello (helps registration behind SNI filters)
	} `json:"aether"`
	Psiphon struct {
		Bin    string `json:"bin"`
		Region string `json:"region"` // e.g. "DE"; empty = best
		Style  string `json:"style"`  // auto | cdn | direct
	} `json:"psiphon"`
	Tor struct {
		Bin         string `json:"bin"`
		BridgesFile string `json:"bridges_file"`
		Bridge      string `json:"bridge"` // auto | obfs4 | snowflake | meek | webtunnel | none
	} `json:"tor"`
}

func defaultConfig() *Config {
	c := &Config{
		Listen:         "127.0.0.1",
		Port:           8888,
		APIPort:        8808,
		Mode:           "",
		Order:          []string{"warp", "psiphon", "tor"},
		HealthURLs:     []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"},
		HealthInterval: 30,
	}
	c.Psiphon.Style = "auto"
	c.Tor.Bridge = "auto"
	c.Warp.Variant, c.Warp.PsiphonVariant, c.Warp.TorVariant = "auto", "auto", "auto"
	c.Aether.Scan, c.Aether.IP, c.Aether.Fragment = "balanced", "4", true
	return c
}

func loadConfig(path string) (*Config, error) {
	c := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func (c *Config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port %d", c.Port)
	}
	if c.APIPort == 0 {
		c.APIPort = 8808
	}
	if c.APIPort == c.Port {
		return fmt.Errorf("port and api_port must differ")
	}
	if c.HealthInterval < 5 {
		c.HealthInterval = 5
	}
	if (c.Username == "") != (c.Password == "") {
		return fmt.Errorf("username and password must be set together")
	}
	ip := net.ParseIP(c.Listen)
	if ip == nil {
		return fmt.Errorf("listen must be an IP address")
	}
	// An open relay on a public interface is how proxies get abused: demand credentials.
	if !ip.IsLoopback() && c.Username == "" {
		return fmt.Errorf("listening on %s without username/password would make an open proxy", c.Listen)
	}
	if c.Mode != "" {
		raw, v := splitMode(c.Mode)
		m := normMode(raw)
		if m == "" {
			return fmt.Errorf("unknown mode %q (use one of: %s)", c.Mode, strings.Join(allModes, ", "))
		}
		c.Mode = m
		if v != "" {
			nv := normVariant(v)
			if nv == "" {
				return fmt.Errorf("unknown WARP variant %q (use one of: %s)", v, strings.Join(warpVariants, ", "))
			}
			c.ModeVariant = nv
		}
	}
	for _, p := range []*string{&c.Warp.Variant, &c.Warp.PsiphonVariant, &c.Warp.TorVariant} {
		if strings.TrimSpace(*p) == "" {
			*p = "auto"
			continue
		}
		nv := normVariant(*p)
		if nv == "" {
			return fmt.Errorf("unknown WARP variant %q (use one of: %s)", *p, strings.Join(warpVariants, ", "))
		}
		*p = nv
	}
	switch strings.ToLower(strings.TrimSpace(c.Aether.Scan)) {
	case "":
		c.Aether.Scan = "balanced"
	case "turbo", "balanced", "thorough", "verified", "ironclad":
		c.Aether.Scan = strings.ToLower(strings.TrimSpace(c.Aether.Scan))
	default:
		return fmt.Errorf("aether.scan must be turbo, balanced, thorough, verified or ironclad")
	}
	switch strings.ToLower(strings.TrimSpace(c.Aether.IP)) {
	case "", "4", "v4", "ipv4":
		c.Aether.IP = "4"
	case "6", "v6", "ipv6":
		c.Aether.IP = "6"
	case "both", "dual":
		c.Aether.IP = "both"
	default:
		return fmt.Errorf("aether.ip must be 4, 6 or both")
	}
	switch strings.ToLower(strings.TrimSpace(c.Aether.Noize)) {
	case "", "off", "light", "firewall", "balanced", "gfw", "aggressive":
		c.Aether.Noize = strings.ToLower(strings.TrimSpace(c.Aether.Noize))
	default:
		return fmt.Errorf("aether.noize must be off, light, firewall, balanced, gfw or aggressive")
	}
	switch strings.ToLower(strings.TrimSpace(c.Psiphon.Style)) {
	case "", "auto":
		c.Psiphon.Style = "auto"
	case "cdn", "direct":
		c.Psiphon.Style = strings.ToLower(strings.TrimSpace(c.Psiphon.Style))
	default:
		return fmt.Errorf("psiphon.style must be auto, cdn or direct")
	}
	switch strings.ToLower(strings.TrimSpace(c.Tor.Bridge)) {
	case "", "auto":
		c.Tor.Bridge = "auto"
	case "obfs4", "snowflake", "meek", "webtunnel", "none":
		c.Tor.Bridge = strings.ToLower(strings.TrimSpace(c.Tor.Bridge))
	default:
		return fmt.Errorf("tor.bridge must be auto, obfs4, snowflake, meek, webtunnel or none")
	}
	if c.DataDir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			d = "."
		}
		c.DataDir = filepath.Join(d, "clubconnect")
	}
	return os.MkdirAll(c.DataDir, 0o700)
}

// ---------- settings chosen from the menu (data_dir/settings.json) ----------

// Once this file exists it holds the complete set of menu-editable values, so clearing a
// value in the menu really clears it (config.json is not consulted again for these keys).
type userSettings struct {
	LastMode      string `json:"last_mode"`
	Port          int    `json:"port"`
	Verbose       bool   `json:"verbose"`
	PsiphonRegion string `json:"psiphon_region"`
	PsiphonStyle  string `json:"psiphon_style"`
	PsiphonBin    string `json:"psiphon_bin"`
	TorBridge     string `json:"tor_bridge"`
	TorBin        string `json:"tor_bin"`
	TorBridges    string `json:"tor_bridges_file"`
	WarpEndpoint  string `json:"warp_endpoint"`

	WarpVariant    string `json:"warp_variant"`
	PsiphonVariant string `json:"warp_psiphon_variant"`
	TorVariant     string `json:"warp_tor_variant"`
	AetherBin      string `json:"aether_bin"`
	AetherScan     string `json:"aether_scan"`
	AetherIP       string `json:"aether_ip"`
	AetherNoize    string `json:"aether_noize"`
	AetherFragment string `json:"aether_fragment"` // "on" | "off" | "" (not chosen yet: keep the default)
}

func (c *Config) settingsPath() string { return filepath.Join(c.DataDir, "settings.json") }

func (c *Config) loadSettings() {
	b, err := os.ReadFile(c.settingsPath())
	if err != nil {
		return
	}
	var s userSettings
	if json.Unmarshal(b, &s) != nil {
		return
	}
	c.LastMode = normMode(s.LastMode)
	if s.Port >= 1 && s.Port <= 65535 {
		c.Port = s.Port
	}
	c.Verbose = s.Verbose
	c.Psiphon.Region = s.PsiphonRegion
	if s.PsiphonStyle != "" {
		c.Psiphon.Style = s.PsiphonStyle
	}
	c.Psiphon.Bin = s.PsiphonBin
	if s.TorBridge != "" {
		c.Tor.Bridge = s.TorBridge
	}
	c.Tor.Bin = s.TorBin
	c.Tor.BridgesFile = s.TorBridges
	if s.WarpEndpoint != "" {
		c.Warp.Endpoints = []string{s.WarpEndpoint}
	} else {
		c.Warp.Endpoints = nil
	}
	// Files written by older versions lack these keys: an empty value keeps the default.
	if v := normVariant(s.WarpVariant); v != "" {
		c.Warp.Variant = v
	}
	if v := normVariant(s.PsiphonVariant); v != "" {
		c.Warp.PsiphonVariant = v
	}
	if v := normVariant(s.TorVariant); v != "" {
		c.Warp.TorVariant = v
	}
	c.Aether.Bin = s.AetherBin
	if s.AetherScan != "" {
		c.Aether.Scan = s.AetherScan
	}
	if s.AetherIP != "" {
		c.Aether.IP = s.AetherIP
	}
	c.Aether.Noize = s.AetherNoize
	switch s.AetherFragment {
	case "on":
		c.Aether.Fragment = true
	case "off":
		c.Aether.Fragment = false
	}
}

// variantFor returns the WARP variant a mode uses (the setting made in the menu or config).
func (c *Config) variantFor(mode string) string {
	var v string
	switch mode {
	case "warp+psiphon":
		v = c.Warp.PsiphonVariant
	case "warp+tor":
		v = c.Warp.TorVariant
	default:
		v = c.Warp.Variant
	}
	if v = normVariant(v); v == "" {
		v = "auto"
	}
	return v
}

func (c *Config) setVariant(mode, v string) {
	switch mode {
	case "warp+psiphon":
		c.Warp.PsiphonVariant = v
	case "warp+tor":
		c.Warp.TorVariant = v
	default:
		c.Warp.Variant = v
	}
}

func (c *Config) saveSettings() {
	s := userSettings{
		LastMode:      c.LastMode,
		Port:          c.Port,
		Verbose:       c.Verbose,
		PsiphonRegion: c.Psiphon.Region,
		PsiphonStyle:  c.Psiphon.Style,
		PsiphonBin:    c.Psiphon.Bin,
		TorBridge:     c.Tor.Bridge,
		TorBin:        c.Tor.Bin,
		TorBridges:    c.Tor.BridgesFile,
	}
	if len(c.Warp.Endpoints) > 0 {
		s.WarpEndpoint = c.Warp.Endpoints[0]
	}
	s.WarpVariant, s.PsiphonVariant, s.TorVariant = c.Warp.Variant, c.Warp.PsiphonVariant, c.Warp.TorVariant
	s.AetherBin, s.AetherScan, s.AetherIP, s.AetherNoize = c.Aether.Bin, c.Aether.Scan, c.Aether.IP, c.Aether.Noize
	s.AetherFragment = "off"
	if c.Aether.Fragment {
		s.AetherFragment = "on"
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(c.settingsPath(), b, 0o600)
}
