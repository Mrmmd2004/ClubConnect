package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		if got := NormMode(in); got != want {
			t.Errorf("NormMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitModeAndVariant(t *testing.T) {
	m, v := SplitMode("warp+tor@masque-h2")
	if NormMode(m) != "warp+tor" || NormVariant(v) != "masque-h2" {
		t.Errorf("SplitMode gave %q %q", m, v)
	}
	if m, v := SplitMode("auto"); m != "auto" || v != "" {
		t.Errorf("SplitMode without variant gave %q %q", m, v)
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
		if got := NormVariant(in); got != want {
			t.Errorf("NormVariant(%q) = %q, want %q", in, got, want)
		}
	}
	for _, v := range WarpVariants {
		if NormVariant(v) != v {
			t.Errorf("variant %q does not survive NormVariant", v)
		}
		if VariantLabels[v] == "" || VariantShort[v] == "" {
			t.Errorf("variant %q has no label", v)
		}
	}
}

func TestEveryModeHasALabelAndRoundTrips(t *testing.T) {
	for _, m := range AllModes {
		if ModeLabel(m) == m {
			t.Errorf("mode %q has no label", m)
		}
		if NormMode(m) != m {
			t.Errorf("mode %q does not survive NormMode", m)
		}
	}
	if ModeLabel("custom") != "custom" {
		t.Error("an unknown mode must pass through ModeLabel")
	}
}

func TestModeUsesWarp(t *testing.T) {
	want := map[string]bool{"auto": true, "warp": true, "warp+psiphon": true, "warp+tor": true, "psiphon": false, "tor": false}
	for m, w := range want {
		if ModeUsesWarp(m) != w {
			t.Errorf("ModeUsesWarp(%q) = %v", m, !w)
		}
	}
}

func TestVariantNeedsAether(t *testing.T) {
	for _, v := range WarpVariants {
		want := v != "wg" && v != "auto"
		if VariantNeedsAether(v) != want {
			t.Errorf("VariantNeedsAether(%q) = %v", v, !want)
		}
	}
	if VariantNeedsAether("") {
		t.Error("an empty variant must not need aether")
	}
}

func TestVariantSettingsPerMode(t *testing.T) {
	c := Default()
	c.SetVariant("warp+tor", "gool")
	c.SetVariant("warp", "masque")
	if c.VariantFor("warp+tor") != "gool" || c.VariantFor("warp") != "masque" {
		t.Error("variant not stored per mode")
	}
	if c.VariantFor("warp+psiphon") != "auto" {
		t.Error("an unset mode must default to auto")
	}
	c.Warp.PsiphonVariant = "garbage"
	if c.VariantFor("warp+psiphon") != "auto" {
		t.Error("an invalid stored variant must read as auto")
	}
}

func TestDefaultsStartNothing(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Mode != "" {
		t.Errorf("default mode must be empty (no auto start), got %q", c.Mode)
	}
	c.Mode = "Cloudflare-Psiphon"
	if err := c.Validate(); err != nil || c.Mode != "warp+psiphon" {
		t.Errorf("mode not normalised: %q %v", c.Mode, err)
	}
	c.Tor.Bridge = "bogus"
	if err := c.Validate(); err == nil {
		t.Error("bogus tor.bridge accepted")
	}
}

// The numbers and names users already rely on must not move.
func TestDefaultValuesAreStable(t *testing.T) {
	c := Default()
	if c.Listen != "127.0.0.1" || c.Port != 1819 || DefaultPort != 1819 || c.APIPort != 8808 || c.HealthInterval != 30 {
		t.Errorf("defaults changed: %+v", c)
	}
	if !reflect.DeepEqual(c.Order, []string{"warp", "psiphon", "tor"}) {
		t.Errorf("auto order changed: %v", c.Order)
	}
	if c.Aether.Scan != "balanced" || c.Aether.IP != "4" || !c.Aether.Fragment || c.Psiphon.Style != "auto" || c.Tor.Bridge != "auto" {
		t.Errorf("engine defaults changed: %+v %+v %+v", c.Aether, c.Psiphon, c.Tor)
	}
}

func TestConfigVariantValidation(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Mode = "warp@masque-h2"
	if err := c.Validate(); err != nil || c.Mode != "warp" || c.ModeVariant != "masque-h2" {
		t.Errorf("mode@variant not understood: %q %q %v", c.Mode, c.ModeVariant, err)
	}
	c.Warp.TorVariant = "bogus"
	if err := c.Validate(); err == nil {
		t.Error("bogus warp.tor_variant accepted")
	}
}

func TestValidateRules(t *testing.T) {
	mk := func(f func(*Config)) error {
		c := Default()
		c.DataDir = t.TempDir()
		f(c)
		return c.Validate()
	}
	bad := map[string]func(*Config){
		"port 0":                  func(c *Config) { c.Port = 0 },
		"port too high":           func(c *Config) { c.Port = 70000 },
		"api port equals port":    func(c *Config) { c.APIPort = c.Port },
		"user without password":   func(c *Config) { c.Username = "u" },
		"listen not an ip":        func(c *Config) { c.Listen = "localhost" },
		"open proxy":              func(c *Config) { c.Listen = "0.0.0.0" },
		"unknown mode":            func(c *Config) { c.Mode = "teleport" },
		"unknown variant in mode": func(c *Config) { c.Mode = "warp@nope" },
		"bad aether scan":         func(c *Config) { c.Aether.Scan = "slow" },
		"bad aether ip":           func(c *Config) { c.Aether.IP = "5" },
		"bad aether noize":        func(c *Config) { c.Aether.Noize = "loud" },
		"bad psiphon style":       func(c *Config) { c.Psiphon.Style = "fast" },
	}
	for name, f := range bad {
		if mk(f) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mk(func(c *Config) { c.Listen, c.Username, c.Password = "0.0.0.0", "u", "p" }); err != nil {
		t.Errorf("a public listener with credentials was refused: %v", err)
	}
	if err := mk(func(c *Config) { c.APIPort = -1 }); err != nil {
		t.Errorf("api_port -1 (off) was refused: %v", err)
	}
	c := Default()
	c.DataDir = t.TempDir()
	c.HealthInterval = 1
	c.Aether.IP, c.Aether.Scan = "IPv6", " Thorough "
	if err := c.Validate(); err != nil || c.HealthInterval != 5 || c.Aether.IP != "6" || c.Aether.Scan != "thorough" {
		t.Errorf("normalisation: %v %d %q %q", err, c.HealthInterval, c.Aether.IP, c.Aether.Scan)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if c, err := Load(filepath.Join(dir, "missing.json")); err != nil || c.Port != 1819 {
		t.Errorf("a missing file must give the defaults: %v", err)
	}
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte(`{"port": 9000, "warp": {"variant": "masque"}, "order": ["tor"]}`), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != 9000 || c.Warp.Variant != "masque" || c.Listen != "127.0.0.1" || len(c.Order) != 1 {
		t.Errorf("loaded %+v", c)
	}
	os.WriteFile(p, []byte(`{not json`), 0o600)
	if _, err := Load(p); err == nil {
		t.Error("a broken config.json was accepted")
	}
}

// ---------- RuntimeSettings ----------

// settings.json exactly as Club Connect v1.0 wrote it.
const settingsV10 = `{
  "last_mode": "warp+tor",
  "port": 8890,
  "verbose": true,
  "psiphon_region": "DE",
  "psiphon_style": "cdn",
  "psiphon_bin": "",
  "tor_bridge": "obfs4",
  "tor_bin": "",
  "tor_bridges_file": "",
  "warp_endpoint": "162.159.192.1:2408",
  "warp_variant": "masque",
  "warp_psiphon_variant": "gool",
  "warp_tor_variant": "wg-noize",
  "aether_bin": "",
  "aether_scan": "thorough",
  "aether_ip": "both",
  "aether_noize": "gfw",
  "aether_fragment": "off"
}`

func TestSettingsFileOfV10LoadsAndSavesIdentically(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	os.WriteFile(c.SettingsPath(), []byte(settingsV10), 0o600)
	c.LoadSettings()
	if c.LastMode != "warp+tor" || c.Port != 8890 || !c.Verbose {
		t.Errorf("basic fields: %q %d %v", c.LastMode, c.Port, c.Verbose)
	}
	if c.Psiphon.Region != "DE" || c.Psiphon.Style != "cdn" || c.Tor.Bridge != "obfs4" {
		t.Errorf("engine fields: %+v %+v", c.Psiphon, c.Tor)
	}
	if !reflect.DeepEqual(c.Warp.Endpoints, []string{"162.159.192.1:2408"}) {
		t.Errorf("endpoint: %v", c.Warp.Endpoints)
	}
	if c.VariantFor("warp") != "masque" || c.VariantFor("warp+psiphon") != "gool" || c.VariantFor("warp+tor") != "wg-noize" {
		t.Error("per-mode variants lost")
	}
	if c.Aether.Scan != "thorough" || c.Aether.IP != "both" || c.Aether.Noize != "gfw" || c.Aether.Fragment {
		t.Errorf("aether: %+v", c.Aether)
	}
	if err := c.SaveSettings(); err != nil {
		t.Fatal(err)
	}
	saved, _ := os.ReadFile(c.SettingsPath())
	var a, b map[string]any
	json.Unmarshal([]byte(settingsV10), &a)
	json.Unmarshal(saved, &b)
	if b["settings_version"] != float64(2) {
		t.Errorf("settings_version = %v, want 2", b["settings_version"])
	}
	delete(b, "settings_version") // the one key v0.8 adds
	if !reflect.DeepEqual(a, b) {
		t.Errorf("round trip changed the file:\n%s", saved)
	}

}

func TestOlderSettingsFileKeepsDefaultsForMissingKeys(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	os.WriteFile(c.SettingsPath(), []byte(`{"last_mode":"tor","port":8899,"psiphon_style":"direct"}`), 0o600)
	c.LoadSettings()
	if c.Warp.Variant != "auto" || c.Warp.PsiphonVariant != "auto" || c.Warp.TorVariant != "auto" {
		t.Errorf("variants should stay auto: %+v", c.Warp)
	}
	if c.Aether.Scan != "balanced" || c.Aether.IP != "4" || c.Tor.Bridge != "auto" {
		t.Errorf("defaults lost: %+v %+v", c.Aether, c.Tor)
	}
	if !c.Aether.Fragment {
		t.Error("aether fragment must keep its default (on) when the file does not say")
	}
	if c.Port != 8899 || c.LastMode != "tor" || c.Psiphon.Style != "direct" {
		t.Errorf("stored values lost: %d %q %q", c.Port, c.LastMode, c.Psiphon.Style)
	}
}

func TestClearingAValueInTheMenuReallyClearsIt(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Psiphon.Region = "NL" // as if config.json said so
	c.Aether.Noize = "gfw"
	os.WriteFile(c.SettingsPath(), []byte(`{"last_mode":"","port":8888,"psiphon_region":"","aether_noize":""}`), 0o600)
	c.LoadSettings()
	if c.Psiphon.Region != "" || c.Aether.Noize != "" {
		t.Errorf("an empty value in settings.json must clear config.json's: %q %q", c.Psiphon.Region, c.Aether.Noize)
	}
}

// Before v0.8 the default port was 8888 and every settings.json recorded it, so an old file's
// 8888 is not a choice: the new default (1819) must win. A deliberate port is kept.
func TestOldDefaultPortMovesToTheNewDefault(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	os.WriteFile(c.SettingsPath(), []byte(`{"last_mode":"auto","port":8888,"psiphon_style":"auto"}`), 0o600)
	c.LoadSettings()
	if c.Port != 1819 {
		t.Errorf("an old file's 8888 gave port %d, want 1819", c.Port)
	}
	if c.LastMode != "auto" {
		t.Error("the other values of the old file were lost")
	}
	// a file written by v0.8 that says 8888 is a real choice
	c2 := Default()
	c2.DataDir = t.TempDir()
	c2.Port = 8888
	c2.SaveSettings()
	c3 := Default()
	c3.DataDir = c2.DataDir
	c3.LoadSettings()
	if c3.Port != 8888 {
		t.Errorf("a chosen 8888 became %d", c3.Port)
	}
	// and any other old port is kept
	c4 := Default()
	c4.DataDir = t.TempDir()
	os.WriteFile(c4.SettingsPath(), []byte(`{"port":9050}`), 0o600)
	c4.LoadSettings()
	if c4.Port != 9050 {
		t.Errorf("an old file's 9050 became %d", c4.Port)
	}
	// saving an old file upgrades it, so the choice is remembered from now on
	c4.SaveSettings()
	b, _ := os.ReadFile(c4.SettingsPath())
	if !strings.Contains(string(b), `"settings_version": 2`) {
		t.Errorf("file not upgraded:\n%s", b)
	}
}

func TestInvalidPortInSettingsIsIgnored(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	os.WriteFile(c.SettingsPath(), []byte(`{"port": 70000}`), 0o600)
	c.LoadSettings()
	if c.Port != 1819 {
		t.Errorf("port = %d", c.Port)
	}
}

func TestDamagedSettingsFileIsIgnored(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.Port = 8123
	os.WriteFile(c.SettingsPath(), []byte(`{"port": 99`), 0o600)
	c.LoadSettings()
	if c.Port != 8123 {
		t.Errorf("a damaged file changed the config: port %d", c.Port)
	}
	c2 := Default()
	c2.DataDir = filepath.Join(t.TempDir(), "nothing-here")
	c2.LoadSettings() // no file at all: must not panic or change anything
	if c2.Port != 1819 {
		t.Error("a missing settings file changed the config")
	}
}

func TestSaveSettingsIsAtomicAndPrivate(t *testing.T) {
	c := Default()
	c.DataDir = t.TempDir()
	c.LastMode = "auto"
	for i := 0; i < 3; i++ {
		if err := c.SaveSettings(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(c.SettingsPath() + ".tmp"); !os.IsNotExist(err) {
		t.Error("a temporary file was left behind")
	}
	if st, err := os.Stat(c.SettingsPath()); err != nil || st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("settings.json must be private (0600): %v %v", st, err)
	}
	c.DataDir = filepath.Join(c.DataDir, "no", "such", "dir")
	if err := c.SaveSettings(); err == nil {
		t.Error("a failed save was not reported")
	}
}

func TestSettingsFromAndApplyToRoundTrip(t *testing.T) {
	c := Default()
	c.LastMode, c.Port, c.Verbose = "warp+psiphon", 8811, true
	c.Warp.Endpoints = []string{"1.2.3.4:500"}
	c.SetVariant("warp", "mim")
	c.Aether.Fragment = false
	c.Tor.BridgesFile = "/x/bridges.txt"
	s := SettingsFrom(c)
	d := Default()
	s.ApplyTo(d)
	if !reflect.DeepEqual(c, d) {
		t.Errorf("round trip lost something:\n%+v\n%+v", c, d)
	}
}

func TestWriteFileAtomicReplaces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	WriteFileAtomic(p, []byte("one"), 0o600)
	WriteFileAtomic(p, []byte("two"), 0o600)
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Errorf("got %q", b)
	}
}
