// Package config holds what Club Connect is told: config.json, the command-line flags applied
// on top of it, and the choices made in the menu (RuntimeSettings, settings.json).
package config

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

// DefaultPort is the proxy port (SOCKS5 + HTTP) when nothing else is chosen. Earlier versions
// used 8888.
const DefaultPort = 1819

// Default is the configuration used when config.json is absent or leaves a value out.
func Default() *Config {
	c := &Config{
		Listen:         "127.0.0.1",
		Port:           DefaultPort,
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

// Load reads config.json; a missing file gives the defaults.
func Load(path string) (*Config, error) {
	c := Default()
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

// Validate checks the configuration, normalises spellings and creates the data directory.
func (c *Config) Validate() error {
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
		raw, v := SplitMode(c.Mode)
		m := NormMode(raw)
		if m == "" {
			return fmt.Errorf("unknown mode %q (use one of: %s)", c.Mode, strings.Join(AllModes, ", "))
		}
		c.Mode = m
		if v != "" {
			nv := NormVariant(v)
			if nv == "" {
				return fmt.Errorf("unknown WARP variant %q (use one of: %s)", v, strings.Join(WarpVariants, ", "))
			}
			c.ModeVariant = nv
		}
	}
	for _, p := range []*string{&c.Warp.Variant, &c.Warp.PsiphonVariant, &c.Warp.TorVariant} {
		if strings.TrimSpace(*p) == "" {
			*p = "auto"
			continue
		}
		nv := NormVariant(*p)
		if nv == "" {
			return fmt.Errorf("unknown WARP variant %q (use one of: %s)", *p, strings.Join(WarpVariants, ", "))
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

// WriteFileAtomic writes data to a temporary file next to path and renames it into place, so a
// crash or a full disk can never leave a half-written file behind.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
