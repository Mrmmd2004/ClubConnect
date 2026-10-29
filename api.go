package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
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
func serveAPI(ctx context.Context, cfg *Config, m *Manager) {
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
	mux.HandleFunc("/status", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.Status())
	}))
	mux.HandleFunc("/switch", guard(func(w http.ResponseWriter, r *http.Request) {
		if err := m.SetMode(r.URL.Query().Get("backend")); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.Status())
	}))
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.APIPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { <-ctx.Done(); srv.Close() }()
	go srv.ListenAndServe()
}
