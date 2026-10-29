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

	Warp struct {
		Endpoints []string `json:"endpoints"`
		WGConf    string   `json:"wg_conf"`
	} `json:"warp"`
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
		m := normMode(c.Mode)
		if m == "" {
			return fmt.Errorf("unknown mode %q (use one of: %s)", c.Mode, strings.Join(allModes, ", "))
		}
		c.Mode = m
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
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(c.settingsPath(), b, 0o600)
}
