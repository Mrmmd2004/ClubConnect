package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"clubconnect/internal/logx"
)

// RuntimeSettings are the choices made while the program runs - the last mode, the WARP variant
// of each mode and everything in the Settings menu. They live in data_dir/settings.json, apart
// from config.json, and the JSON field names below are the file format (older versions wrote
// the same names).
//
// Once the file exists it holds the complete set of menu-editable values, so clearing a value in
// the menu really clears it (config.json is not consulted again for these keys).
type RuntimeSettings struct {
	// Version of the file format. Files written before v0.8 have none (0); for those, a port of
	// 8888 is the old default and not a choice, so it is ignored in favour of DefaultPort.
	Version int `json:"settings_version"`

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

// settingsVersion is the version written by this program.
const settingsVersion = 2

// legacyDefaultPort was the proxy port before v0.8.
const legacyDefaultPort = 8888

var saveMu sync.Mutex

// SettingsPath is where RuntimeSettings are kept.
func (c *Config) SettingsPath() string { return filepath.Join(c.DataDir, "settings.json") }

// SettingsFrom captures the menu-editable values of c.
func SettingsFrom(c *Config) RuntimeSettings {
	s := RuntimeSettings{
		Version:       settingsVersion,
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
	return s
}

// ApplyTo overlays the settings on c. Values that older versions did not write (empty strings
// for the newer keys) keep what c already has.
func (s RuntimeSettings) ApplyTo(c *Config) {
	c.LastMode = NormMode(s.LastMode)
	if s.Port >= 1 && s.Port <= 65535 && !(s.Version < 2 && s.Port == legacyDefaultPort) {
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
	if v := NormVariant(s.WarpVariant); v != "" {
		c.Warp.Variant = v
	}
	if v := NormVariant(s.PsiphonVariant); v != "" {
		c.Warp.PsiphonVariant = v
	}
	if v := NormVariant(s.TorVariant); v != "" {
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

// LoadSettings overlays data_dir/settings.json on c. A missing file changes nothing; a damaged
// one is reported and ignored.
func (c *Config) LoadSettings() {
	b, err := os.ReadFile(c.SettingsPath())
	if err != nil {
		return
	}
	var s RuntimeSettings
	if err := json.Unmarshal(b, &s); err != nil {
		logx.For("config").Warnf("%s is damaged and was ignored: %v", c.SettingsPath(), err)
		return
	}
	s.ApplyTo(c)
}

// SaveSettings writes the menu-editable values of c to data_dir/settings.json (atomically).
func (c *Config) SaveSettings() error {
	saveMu.Lock()
	defer saveMu.Unlock()
	b, err := json.MarshalIndent(SettingsFrom(c), "", "  ")
	if err != nil {
		return err
	}
	if err := WriteFileAtomic(c.SettingsPath(), b, 0o600); err != nil {
		logx.For("config").Warnf("cannot save settings: %v", err)
		return err
	}
	return nil
}
