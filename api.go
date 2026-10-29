package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

type backendStatus struct {
	Name      string `json:"name"`
	Ready     bool   `json:"ready"`
	Healthy   bool   `json:"healthy"`
	LatencyMS int64  `json:"latency_ms"`
	UDP       bool   `json:"udp"`
	Error     string `json:"error,omitempty"`
}

type status struct {
	Version  string          `json:"version"`
	Running  bool            `json:"running"`
	RunMode  string          `json:"run_mode"`
	LastMode string          `json:"last_mode"`
	Port     int             `json:"port"`
	Mode     string          `json:"mode"`
	Active   string          `json:"active"`
	Up       uint64          `json:"bytes_up"`
	Down     uint64          `json:"bytes_down"`
	Backends []backendStatus `json:"backends"`
}

func (m *Manager) Status() status {
	st := status{Version: Version, Up: m.up.Load(), Down: m.down.Load()}
	st.Mode, _ = m.mode.Load().(string)
	if i := int(m.active.Load()); i >= 0 && i < len(m.bs) {
		st.Active = m.bs[i].b.Name()
	}
	for _, s := range m.bs {
		h, l := s.snapshot()
		st.Backends = append(st.Backends, backendStatus{
			Name: s.b.Name(), Ready: s.b.Ready(), Healthy: h,
			LatencyMS: l.Milliseconds(), UDP: s.b.SupportsUDP(), Error: s.b.LastError(),
		})
	}
	return st
}

// Control API for the app that embeds the core. Loopback only.
//
//	GET /status
//	GET /start?mode=auto|warp|psiphon|tor|warp+psiphon|warp+tor
//	GET /stop
//	GET /switch?backend=...   (inside the running mode)
//	GET /test
func serveAPI(ctx context.Context, cfg *Config, ctl *Controller) {
	if cfg.APIPort < 0 {
		return
	}
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if cfg.APIToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(cfg.APIToken)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	reply := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ctl.Status())
	}
	mux.HandleFunc("/status", guard(func(w http.ResponseWriter, r *http.Request) { reply(w) }))
	mux.HandleFunc("/start", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := ctl.Start(r.URL.Query().Get("mode")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply(w)
	}))
	mux.HandleFunc("/stop", guard(func(w http.ResponseWriter, r *http.Request) {
		ctl.Stop()
		reply(w)
	}))
	mux.HandleFunc("/switch", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := ctl.Switch(r.URL.Query().Get("backend")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply(w)
	}))
	mux.HandleFunc("/test", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, ctl.Test())
	}))
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.APIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { <-ctx.Done(); srv.Close() }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("[api] cannot listen on %s: %v", srv.Addr, err)
		}
	}()
}
