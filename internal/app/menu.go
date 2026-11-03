package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"clubconnect/internal/backends"
	"clubconnect/internal/config"
)

// IsTerminal reports whether f is an interactive terminal (a console window, not a pipe).
func IsTerminal(f *os.File) bool {
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

func printMenu(ctl *Controller, cfg *config.Config) {
	running, mode := ctl.Running()
	fmt.Println()
	fmt.Printf("================ %s v%s ================\n", ctl.info.Name, ctl.info.Version)
	if running {
		if config.ModeUsesWarp(mode) {
			fmt.Printf(" Status : RUNNING - %s  [WARP: %s]\n          proxy %s:%d (SOCKS5 + HTTP)\n", config.ModeLabel(mode), config.VariantName(ctl.RunVariant()), cfg.Listen, cfg.Port)
		} else {
			fmt.Printf(" Status : RUNNING - %s\n          proxy %s:%d (SOCKS5 + HTTP)\n", config.ModeLabel(mode), cfg.Listen, cfg.Port)
		}
	} else {
		fmt.Println(" Status : STOPPED - nothing runs until you pick a mode")
	}
	fmt.Printf(" Engines: warp built-in | aether %s | psiphon %s | tor %s\n", okMissing(backends.AetherBin(cfg)), okMissing(backends.PsiphonBin(cfg)), okMissing(backends.TorBin(cfg)))
	fmt.Println()
	fmt.Printf("  1) Auto                  best of WARP / Psiphon / Tor, switches by itself  [WARP: %s]\n", config.VariantName(cfg.VariantFor("auto")))
	fmt.Printf("  2) WARP only                                                                [WARP: %s]\n", config.VariantName(cfg.VariantFor("warp")))
	fmt.Println("  3) Psiphon only")
	fmt.Println("  4) Tor only")
	fmt.Printf("  5) WARP -> Psiphon       Psiphon connects through WARP                      [WARP: %s]\n", config.VariantName(cfg.VariantFor("warp+psiphon")))
	fmt.Printf("  6) WARP -> Tor           Tor connects through WARP                          [WARP: %s]\n", config.VariantName(cfg.VariantFor("warp+tor")))
	fmt.Println("  7) Test connection       real request through the proxy + exit IP")
	fmt.Println("  8) Status")
	fmt.Println("  9) Settings")
	fmt.Println("  S) Stop (keep this window)")
	fmt.Println("  0) Close this menu - what is running keeps running")
	fmt.Println("  Q) Stop and exit")
	fmt.Println("  (modes 1, 2, 5, 6 ask which WARP variant to use; Enter keeps the one shown)")
	if !running && cfg.LastMode != "" {
		fmt.Printf("  Enter) start the last mode: %s\n", config.ModeLabel(cfg.LastMode))
	}
}

// chooseVariant lists the WARP variants for a mode; Enter keeps the current one.
func chooseVariant(cfg *config.Config, mode string, ask func(string) (string, bool)) {
	cur := cfg.VariantFor(mode)
	fmt.Println()
	fmt.Printf("  WARP variant for \"%s\"   (Enter = keep: %s)\n", config.ModeLabel(mode), config.VariantName(cur))
	for i, v := range config.WarpVariants {
		note := ""
		if !backends.VariantAvailable(cfg, v) {
			note = "   <- needs aether next to clubconnect"
		}
		mark := " "
		if v == cur {
			mark = "*"
		}
		fmt.Printf("   %s%d) %s%s\n", mark, i+1, config.VariantLabels[v], note)
	}
	in, ok := ask("  variant> ")
	if !ok || in == "" {
		return
	}
	n, err := strconv.Atoi(in)
	var v string
	if err == nil && n >= 1 && n <= len(config.WarpVariants) {
		v = config.WarpVariants[n-1]
	} else {
		v = config.NormVariant(in)
	}
	if v == "" {
		fmt.Println("  not a valid choice, keeping", config.VariantName(cur))
		return
	}
	cfg.SetVariant(mode, v)
	cfg.SaveSettings()
}

// RunMenu shows the interactive menu on the keyboard until the user leaves.
func RunMenu(ctx context.Context, ctl *Controller, cfg *config.Config) {
	RunMenuFrom(ctx, ctl, cfg, os.Stdin)
}

// RunMenuFrom is RunMenu reading its keys from in (the tests feed it text).
//
// 0 closes the menu only: a running mode keeps running and Enter brings the menu back. Q (or
// Ctrl+C) stops everything and exits.
func RunMenuFrom(ctx context.Context, ctl *Controller, cfg *config.Config, in io.Reader) {
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(in)
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
		fmt.Printf("  started: %s\n  watch the log lines below; press 7 to test when it says healthy / established / bootstrapped.\n", config.ModeLabel(m))
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
			if m := modes[choice]; config.ModeUsesWarp(m) {
				chooseVariant(cfg, m, ask)
			}
			begin(modes[choice])
		case "7":
			fmt.Println("  testing (up to 25 s)...")
			fmt.Print(ctl.Test())
		case "8":
			st := ctl.Status()
			if !st.Running {
				fmt.Println("  stopped. last mode:", orDefault(config.ModeLabel(st.LastMode), "none"))
				break
			}
			fmt.Printf("  mode %s, active engine: %s, up %d B, down %d B\n", config.ModeLabel(st.RunMode), orDefault(st.Active, "(none yet)"), st.Up, st.Down)
			if config.ModeUsesWarp(st.RunMode) {
				fmt.Printf("  WARP variant: %s\n", config.VariantName(st.Variant))
			}
			for _, b := range st.Backends {
				fmt.Printf("  [%s%s] ready=%v healthy=%v latency=%dms %s\n", b.Name, orDefault(" "+b.Variant, ""), b.Ready, b.Healthy, b.LatencyMS, b.Error)
			}
		case "9":
			settingsMenu(ctl, cfg, ask)
		case "s":
			ctl.Stop()
		case "0":
			running, _ := ctl.Running()
			if !running {
				return // nothing is running: leaving the menu ends the program
			}
			fmt.Printf("  menu closed - %s keeps running on %s:%d. Press Enter to open the menu again, Ctrl+C to stop.\n", ctl.info.Name, cfg.Listen, cfg.Port)
			if _, ok := ask(""); !ok {
				<-ctx.Done()
				return
			}
		case "q", "x", "exit":
			ctl.Stop()
			return
		default:
			fmt.Println("  ?")
		}
	}
}

func settingsMenu(ctl *Controller, cfg *config.Config, ask func(string) (string, bool)) {
	changed := false
	for {
		fmt.Println()
		fmt.Println("---------------- Settings ----------------")
		fmt.Printf("  1) Proxy port             [%d]\n", cfg.Port)
		fmt.Printf("  2) Psiphon region         [%s]   e.g. DE, US, NL, GB (empty = best)\n", orDefault(cfg.Psiphon.Region, "best"))
		fmt.Printf("  3) Psiphon protocols      [%s]   auto | cdn | direct\n", cfg.Psiphon.Style)
		fmt.Printf("  4) Psiphon program path   [%s]\n", orDefault(cfg.Psiphon.Bin, "auto-detect: "+okMissing(backends.PsiphonBin(cfg))))
		fmt.Printf("  5) Tor bridge type        [%s]   auto | obfs4 | snowflake | meek | webtunnel | none\n", cfg.Tor.Bridge)
		fmt.Printf("  6) Tor program path       [%s]\n", orDefault(cfg.Tor.Bin, "auto-detect: "+okMissing(backends.TorBin(cfg))))
		fmt.Printf("  7) Tor bridges file       [%s]   your own bridge lines\n", orDefault(cfg.Tor.BridgesFile, "built-in"))
		ep := ""
		if len(cfg.Warp.Endpoints) > 0 {
			ep = cfg.Warp.Endpoints[0]
		}
		fmt.Printf("  8) WARP endpoint          [%s]   ip:port (empty = automatic)\n", orDefault(ep, "automatic"))
		fmt.Println("  9) WARP: forget this device and register a new free one")
		fmt.Printf("  A) Verbose log            [%s]   shows every failed connection\n", onOff(cfg.Verbose))
		fmt.Printf("  B) Aether program path    [%s]\n", orDefault(cfg.Aether.Bin, "auto-detect: "+okMissing(backends.AetherBin(cfg))))
		fmt.Printf("  C) Aether scan mode       [%s]   turbo | balanced | thorough | verified | ironclad\n", cfg.Aether.Scan)
		fmt.Printf("  D) Aether IP version      [%s]   4 | 6 | both\n", cfg.Aether.IP)
		fmt.Printf("  E) Aether noize           [%s]   handshake disguise: off | light | firewall | balanced | gfw | aggressive\n", orDefault(cfg.Aether.Noize, "aether default"))
		fmt.Printf("  F) Aether TLS fragment    [%s]   splits the TLS hello; helps registration behind SNI filters\n", onOff(cfg.Aether.Fragment))
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
			backends.ResetWarpIdentity(cfg.DataDir)
			fmt.Println("  done - a new free WARP device is registered the next time WARP starts")
			changed = true
		case "a":
			cfg.Verbose, changed = !cfg.Verbose, true
		case "b":
			v, _ := ask("  full path of aether / aether.exe (empty = auto): ")
			cfg.Aether.Bin, changed = strings.Trim(v, "\""), true
		case "c":
			v, _ := ask("  turbo | balanced | thorough | verified | ironclad: ")
			v = strings.ToLower(v)
			switch v {
			case "turbo", "balanced", "thorough", "verified", "ironclad":
				cfg.Aether.Scan, changed = v, true
			default:
				fmt.Println("  not valid")
				continue
			}
		case "d":
			v, _ := ask("  4 | 6 | both: ")
			v = strings.ToLower(v)
			if v != "4" && v != "6" && v != "both" {
				fmt.Println("  not valid")
				continue
			}
			cfg.Aether.IP, changed = v, true
		case "e":
			v, _ := ask("  off | light | firewall | balanced | gfw | aggressive (empty = aether default): ")
			v = strings.ToLower(v)
			switch v {
			case "", "off", "light", "firewall", "balanced", "gfw", "aggressive":
				cfg.Aether.Noize, changed = v, true
			default:
				fmt.Println("  not valid")
				continue
			}
		case "f":
			cfg.Aether.Fragment, changed = !cfg.Aether.Fragment, true
		case "0", "":
			if changed {
				cfg.SaveSettings()
				if running, mode := ctl.Running(); running {
					if a, _ := ask("  restart " + config.ModeLabel(mode) + " now to apply? [y/N] "); strings.ToLower(a) == "y" {
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
