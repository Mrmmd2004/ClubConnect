package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var Version = "0.8"

const Name = "Club Connect"

func main() {
	cfgPath := flag.String("c", "config.json", "config file (optional)")
	dataDir := flag.String("d", "", "data directory")
	port := flag.Int("port", 0, "proxy port (default 8888)")
	order := flag.String("order", "", "backends in priority order, e.g. warp,psiphon,tor")
	mode := flag.String("mode", "", "auto, warp, psiphon or tor")
	ver := flag.Bool("v", false, "print version")
	flag.Parse()
	if *ver {
		fmt.Printf("%s %s\n", Name, Version)
		return
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
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
		log.Fatal(err)
	}

	var bs []Backend
	for _, n := range cfg.Order {
		switch strings.TrimSpace(n) {
		case "warp":
			bs = append(bs, NewWarp(cfg))
		case "psiphon":
			bs = append(bs, NewPsiphon(cfg))
		case "tor":
			bs = append(bs, NewTor(cfg))
		default:
			log.Fatalf("unknown backend %q", n)
		}
	}
	if len(bs) == 0 {
		log.Fatal("no backends enabled")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("%s v%s - proxy on %s:%d (SOCKS5 + HTTP)", Name, Version, cfg.Listen, cfg.Port)

	m := NewManager(cfg, bs)
	go m.Run(ctx)
	serveAPI(ctx, cfg, m)
	if err := (&Inbound{m: m, cfg: cfg}).Serve(ctx); err != nil {
		log.Fatal(err)
	}
}
