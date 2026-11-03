package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"clubconnect/internal/api"
	"clubconnect/internal/app"
	"clubconnect/internal/bundle"
	"clubconnect/internal/config"
	"clubconnect/internal/logx"
)

var Version = "0.8.1"

const Name = "Club Connect"

// fatal prints the problem and, when started by double-click, waits so the window stays readable.
func fatal(err error) {
	logx.For("").Error(err.Error())
	if app.IsTerminal(os.Stdin) {
		fmt.Print("press Enter to close... ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(1)
}

func main() {
	logx.Init()
	cfgPath := flag.String("c", "config.json", "config file (optional)")
	dataDir := flag.String("d", "", "data directory")
	port := flag.Int("port", 0, "proxy port (default 1819)")
	order := flag.String("order", "", "engines used by auto mode, priority order, e.g. warp,psiphon,tor")
	mode := flag.String("mode", "", "start this mode at once: auto, warp, psiphon, tor, warp+psiphon, warp+tor; \"warp@masque\" also picks the WARP variant (default: start nothing, show the menu)")
	variant := flag.String("variant", "", "WARP variant for this start: auto, wg, masque, masque-h2, gool, gool-classic, mim, wg-noize")
	menu := flag.Bool("menu", false, "show the menu even when -mode is given")
	ver := flag.Bool("v", false, "print version")
	flag.Parse()
	if *ver {
		fmt.Printf("%s %s\n", Name, Version)
		return
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if err := cfg.Validate(); err != nil {
		fatal(err)
	}
	cfg.LoadSettings() // choices made in the menu last time
	if *port != 0 {
		cfg.Port = *port
	}
	if *order != "" {
		cfg.Order = strings.Split(*order, ",")
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if err := cfg.Validate(); err != nil {
		fatal(err)
	}
	if *variant != "" {
		nv := config.NormVariant(*variant)
		if nv == "" {
			fatal(fmt.Errorf("unknown WARP variant %q (use one of: %s)", *variant, strings.Join(config.WarpVariants, ", ")))
		}
		cfg.ModeVariant = nv
	}

	log := logx.For("")
	log.Infof("%s v%s", Name, Version)
	// The helper programs (aether, psiphon, lyrebird, snowflake) are inside this executable in
	// release builds: unpack them where the engines look for them.
	if names, err := bundle.Extract(filepath.Join(cfg.DataDir, "bin")); err != nil {
		logx.For("core").Warnf("cannot unpack the built-in helper programs: %v", err)
	} else if len(names) > 0 {
		logx.For("core").Infof("unpacked %s", strings.Join(names, ", "))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctl := app.NewController(ctx, cfg, app.Info{Name: Name, Version: Version})
	api.Serve(ctx, api.Options{Port: cfg.APIPort, Token: cfg.APIToken}, ctl)

	if cfg.Mode != "" {
		if err := ctl.Start(cfg.Mode); err != nil {
			fatal(err)
		}
	}
	switch {
	case app.IsTerminal(os.Stdin) && (cfg.Mode == "" || *menu):
		app.RunMenu(ctx, ctl, cfg)
	case cfg.Mode == "":
		log.Infof("idle: nothing is running. Start a mode with  GET http://127.0.0.1:%d/start?mode=auto  or run with -mode", cfg.APIPort)
		<-ctx.Done()
	default:
		<-ctx.Done()
	}
	ctl.Stop()
}
