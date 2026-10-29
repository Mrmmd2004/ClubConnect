package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	Mode           string   `json:"mode"`  // "auto" or one backend name
	Order          []string `json:"order"` // enabled backends, priority order
	HealthURLs     []string `json:"health_urls"`
	HealthInterval int      `json:"health_interval_sec"`

	Warp struct {
		Endpoints []string `json:"endpoints"`
		WGConf    string   `json:"wg_conf"`
	} `json:"warp"`
	Psiphon struct {
		Bin    string `json:"bin"`
		Region string `json:"region"` // e.g. "DE"; empty = best
	} `json:"psiphon"`
	Tor struct {
		Bin         string `json:"bin"`
		BridgesFile string `json:"bridges_file"`
	} `json:"tor"`
}

func defaultConfig() *Config {
	c := &Config{
		Listen:         "127.0.0.1",
		Port:           8888,
		APIPort:        8808,
		Mode:           "auto",
		Order:          []string{"warp", "psiphon", "tor"},
		HealthURLs:     []string{"http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"},
		HealthInterval: 30,
	}
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
	if c.DataDir == "" {
		d, err := os.UserConfigDir()
		if err != nil {
			d = "."
		}
		c.DataDir = filepath.Join(d, "clubconnect")
	}
	return os.MkdirAll(c.DataDir, 0o700)
}
