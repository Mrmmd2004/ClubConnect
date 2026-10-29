package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var Version = "0.9"

const Name = "Club Connect"

// fatal prints the problem and, when started by double-click, waits so the window stays readable.
func fatal(err error) {
	log.Print(err)
	if isTerminal(os.Stdin) {
		fmt.Print("press Enter to close... ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(1)
}

func main() {
	cfgPath := flag.String("c", "config.json", "config file (optional)")
	dataDir := flag.String("d", "", "data directory")
	port := flag.Int("port", 0, "proxy port (default 8888)")
	order := flag.String("order", "", "engines used by auto mode, priority order, e.g. warp,psiphon,tor")
	mode := flag.String("mode", "", "start this mode at once: auto, warp, psiphon, tor, warp+psiphon, warp+tor (default: start nothing, show the menu)")
	menu := flag.Bool("menu", false, "show the menu even when -mode is given")
	ver := flag.Bool("v", false, "print version")
	flag.Parse()
	if *ver {
		fmt.Printf("%s %s\n", Name, Version)
		return
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if err := cfg.validate(); err != nil {
		fatal(err)
	}
	cfg.loadSettings() // choices made in the menu last time
	if *port != 0 {
		cfg.Port = *port
	}
	if *order != "" {
		cfg.Order = strings.Split(*order, ",")
	}
	if *mode != "" {
		cfg.Mode = *mode
	}
	if err := cfg.validate(); err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctl := NewController(ctx, cfg)
	serveAPI(ctx, cfg, ctl)
	log.Printf("%s v%s", Name, Version)

	if cfg.Mode != "" {
		if err := ctl.Start(cfg.Mode); err != nil {
			fatal(err)
		}
	}
	switch {
	case isTerminal(os.Stdin) && (cfg.Mode == "" || *menu):
		runMenu(ctx, ctl, cfg)
	case cfg.Mode == "":
		log.Printf("idle: nothing is running. Start a mode with  GET http://127.0.0.1:%d/start?mode=auto  or run with -mode", cfg.APIPort)
		<-ctx.Done()
	default:
		<-ctx.Done()
	}
	ctl.Stop()
}
