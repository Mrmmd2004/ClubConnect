package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func okMissing(path string) string {
	if path == "" {
		return "MISSING"
	}
	return "ok"
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func printMenu(ctl *Controller, cfg *Config) {
	running, mode := ctl.Running()
	fmt.Println()
	fmt.Printf("================ %s v%s ================\n", Name, Version)
	if running {
		fmt.Printf(" Status : RUNNING - %s\n          proxy %s:%d (SOCKS5 + HTTP)\n", modeLabel(mode), cfg.Listen, cfg.Port)
	} else {
		fmt.Println(" Status : STOPPED - nothing runs until you pick a mode")
	}
	fmt.Printf(" Engines: warp built-in | psiphon %s | tor %s\n", okMissing(psiphonBin(cfg)), okMissing(torBin(cfg)))
	fmt.Println()
	fmt.Println("  1) Auto                  best of WARP / Psiphon / Tor, switches by itself")
	fmt.Println("  2) WARP only             Cloudflare WARP")
	fmt.Println("  3) Psiphon only")
	fmt.Println("  4) Tor only")
	fmt.Println("  5) Cloudflare -> Psiphon Psiphon connects through WARP")
	fmt.Println("  6) Cloudflare -> Tor     Tor connects through WARP")
	fmt.Println("  7) Test connection       real request through the proxy + exit IP")
	fmt.Println("  8) Status")
	fmt.Println("  9) Settings")
	fmt.Println("  S) Stop (keep this window)")
	fmt.Println("  0) Stop and exit")
	if !running && cfg.LastMode != "" {
		fmt.Printf("  Enter) start the last mode: %s\n", modeLabel(cfg.LastMode))
	}
}

func runMenu(ctx context.Context, ctl *Controller, cfg *Config) {
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	ask := func(prompt string) (string, bool) {
		fmt.Print(prompt)
		select {
		case l, ok := <-lines:
			if !ok {
				return "", false
			}
			return strings.TrimSpace(l), true
		case <-ctx.Done():
			return "", false
		}
	}
	begin := func(m string) {
		if err := ctl.Start(m); err != nil {
			fmt.Println("  cannot start:", err)
			return
		}
		fmt.Printf("  started: %s\n  watch the log lines below; press 7 to test when it says healthy / established / bootstrapped.\n", modeLabel(m))
	}
	modes := map[string]string{"1": "auto", "2": "warp", "3": "psiphon", "4": "tor", "5": "warp+psiphon", "6": "warp+tor"}
	for ctx.Err() == nil {
		printMenu(ctl, cfg)
		choice, ok := ask("> ")
		if !ok {
			<-ctx.Done() // no keyboard (stdin closed): keep serving until stopped
			return
		}
		switch strings.ToLower(choice) {
		case "":
			if running, _ := ctl.Running(); !running && cfg.LastMode != "" {
				begin(cfg.LastMode)
			}
		case "1", "2", "3", "4", "5", "6":
			begin(modes[choice])
		case "7":
			fmt.Println("  testing (up to 25 s)...")
			fmt.Print(ctl.Test())
		case "8":
			st := ctl.Status()
			if !st.Running {
				fmt.Println("  stopped. last mode:", orDefault(modeLabel(st.LastMode), "none"))
				break
			}
			fmt.Printf("  mode %s, active engine: %s, up %d B, down %d B\n", modeLabel(st.RunMode), orDefault(st.Active, "(none yet)"), st.Up, st.Down)
			for _, b := range st.Backends {
				fmt.Printf("  [%s] ready=%v healthy=%v latency=%dms %s\n", b.Name, b.Ready, b.Healthy, b.LatencyMS, b.Error)
			}
		case "9":
			settingsMenu(ctl, cfg, ask)
		case "s":
			ctl.Stop()
		case "0", "q", "x", "exit":
			ctl.Stop()
			return
		default:
			fmt.Println("  ?")
		}
	}
}

func settingsMenu(ctl *Controller, cfg *Config, ask func(string) (string, bool)) {
	changed := false
	for {
		fmt.Println()
		fmt.Println("---------------- Settings ----------------")
		fmt.Printf("  1) Proxy port             [%d]\n", cfg.Port)
		fmt.Printf("  2) Psiphon region         [%s]   e.g. DE, US, NL, GB (empty = best)\n", orDefault(cfg.Psiphon.Region, "best"))
		fmt.Printf("  3) Psiphon protocols      [%s]   auto | cdn | direct\n", cfg.Psiphon.Style)
		fmt.Printf("  4) Psiphon program path   [%s]\n", orDefault(cfg.Psiphon.Bin, "auto-detect: "+okMissing(psiphonBin(cfg))))
		fmt.Printf("  5) Tor bridge type        [%s]   auto | obfs4 | snowflake | meek | webtunnel | none\n", cfg.Tor.Bridge)
		fmt.Printf("  6) Tor program path       [%s]\n", orDefault(cfg.Tor.Bin, "auto-detect: "+okMissing(torBin(cfg))))
		fmt.Printf("  7) Tor bridges file       [%s]   your own bridge lines\n", orDefault(cfg.Tor.BridgesFile, "built-in"))
		ep := ""
		if len(cfg.Warp.Endpoints) > 0 {
			ep = cfg.Warp.Endpoints[0]
		}
		fmt.Printf("  8) WARP endpoint          [%s]   ip:port (empty = automatic)\n", orDefault(ep, "automatic"))
		fmt.Println("  9) WARP: forget this device and register a new free one")
		fmt.Printf("  A) Verbose log            [%s]   shows every failed connection\n", onOff(cfg.Verbose))
		fmt.Println("  0) Back")
		c, ok := ask("settings> ")
		if !ok {
			return
		}
		switch strings.ToLower(c) {
		case "1":
			v, _ := ask("  new port (1024-65535): ")
			n, err := strconv.Atoi(v)
			if err != nil || n < 1024 || n > 65535 || n == cfg.APIPort {
				fmt.Println("  not a valid port")
				continue
			}
			cfg.Port, changed = n, true
		case "2":
			v, _ := ask("  region code, or empty for best: ")
			v = strings.ToUpper(v)
			if v != "" && len(v) != 2 {
				fmt.Println("  use a 2-letter country code")
				continue
			}
			cfg.Psiphon.Region, changed = v, true
		case "3":
			v, _ := ask("  auto | cdn | direct: ")
			v = strings.ToLower(v)
			if v != "auto" && v != "cdn" && v != "direct" {
				fmt.Println("  not valid")
				continue
			}
			cfg.Psiphon.Style, changed = v, true
		case "4":
			v, _ := ask("  full path of psiphon-tunnel-core (empty = auto): ")
			cfg.Psiphon.Bin, changed = strings.Trim(v, "\""), true
		case "5":
			v, _ := ask("  auto | obfs4 | snowflake | meek | webtunnel | none: ")
			v = strings.ToLower(v)
			switch v {
			case "auto", "obfs4", "snowflake", "meek", "webtunnel", "none":
				cfg.Tor.Bridge, changed = v, true
			default:
				fmt.Println("  not valid")
				continue
			}
		case "6":
			v, _ := ask("  full path of tor / tor.exe (empty = auto): ")
			cfg.Tor.Bin, changed = strings.Trim(v, "\""), true
		case "7":
			v, _ := ask("  path of a text file with Bridge lines (empty = built-in): ")
			cfg.Tor.BridgesFile, changed = strings.Trim(v, "\""), true
		case "8":
			v, _ := ask("  endpoint ip:port, e.g. 162.159.192.1:2408 (empty = automatic): ")
			if v == "" {
				cfg.Warp.Endpoints = nil
			} else {
				cfg.Warp.Endpoints = []string{v}
			}
			os.Remove(cfg.DataDir + string(os.PathSeparator) + "warp-endpoint.txt")
			changed = true
		case "9":
			resetWarpIdentity(cfg.DataDir)
			fmt.Println("  done - a new free WARP device is registered the next time WARP starts")
			changed = true
		case "a":
			cfg.Verbose, changed = !cfg.Verbose, true
		case "0", "":
			if changed {
				cfg.saveSettings()
				if running, mode := ctl.Running(); running {
					if a, _ := ask("  restart " + modeLabel(mode) + " now to apply? [y/N] "); strings.ToLower(a) == "y" {
						if err := ctl.Start(mode); err != nil {
							fmt.Println("  cannot restart:", err)
						}
					}
				}
			}
			return
		default:
			fmt.Println("  ?")
		}
	}
}
