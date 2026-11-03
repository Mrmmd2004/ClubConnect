// Package api is the small control API (loopback only) for the app that embeds the core.
//
//	GET /status
//	GET /start?mode=auto|warp|psiphon|tor|warp+psiphon|warp+tor[&variant=auto|wg|masque|masque-h2|gool|gool-classic|mim|wg-noize]
//	GET /variants                  (the WARP variants and whether each can run here)
//	GET /stop
//	GET /switch?backend=...   (inside the running mode)
//	GET /test
//
// Because these are plain GET requests on a local port, the API also refuses what a web page in
// the user's browser could send: a request whose Host is not a loopback name (DNS rebinding) or
// that the browser marks as cross-site.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"clubconnect/internal/core"
	"clubconnect/internal/logx"
)

// Variant is one entry of GET /variants.
type Variant struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Available bool   `json:"available"`
}

// Controller is what the API drives (app.Controller).
type Controller interface {
	Status() core.Status
	Start(spec string) error
	Stop()
	Switch(backend string) error
	Test() string
	Variants() []Variant
}

// Options configures the API server.
type Options struct {
	Port  int    // < 0 = API off
	Token string // when set, requests must carry it in the X-Token header
}

// Handler builds the HTTP handler (exposed for tests).
func Handler(opts Options, ctl Controller) http.Handler {
	mux := http.NewServeMux()
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !localRequest(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if opts.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(opts.Token)) != 1 {
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
	mux.HandleFunc("/variants", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ctl.Variants())
	}))
	mux.HandleFunc("/start", guard(func(w http.ResponseWriter, r *http.Request) {
		spec := r.URL.Query().Get("mode")
		if v := r.URL.Query().Get("variant"); v != "" && !strings.Contains(spec, "@") {
			spec += "@" + v
		}
		if err := ctl.Start(spec); err != nil {
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
	return mux
}

// localRequest tells a request from a program on this machine from one a web page made.
func localRequest(r *http.Request) bool {
	if !loopbackHost(r.Host) {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
	default: // "cross-site", "same-site": a page in a browser, not an app
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		if err != nil || !loopbackHost(u.Host) {
			return false
		}
	} else if o == "null" {
		return false
	}
	return true
}

func loopbackHost(hostport string) bool {
	h := hostport
	if hh, _, err := net.SplitHostPort(hostport); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Serve runs the API on 127.0.0.1:Port until ctx ends. It returns at once; a port that cannot
// be bound is reported in the log.
func Serve(ctx context.Context, opts Options, ctl Controller) {
	if opts.Port < 0 {
		return
	}
	srv := &http.Server{
		Addr:              net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.Port)),
		Handler:           Handler(opts, ctl),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { <-ctx.Done(); srv.Close() }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && ctx.Err() == nil {
			logx.For("api").Infof("cannot listen on %s: %v", srv.Addr, err)
		}
	}()
}
