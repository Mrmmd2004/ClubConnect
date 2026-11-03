package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"clubconnect/internal/core"
	"clubconnect/internal/logx"
)

func TestMain(m *testing.M) {
	logx.InitWriter(io.Discard, slog.LevelError)
	os.Exit(m.Run())
}

type fakeCtl struct {
	started  string
	stopped  int
	switched string
	startErr error
}

func (f *fakeCtl) Status() core.Status {
	return core.Status{Version: "9.9", Running: f.started != "", RunMode: f.started, Backends: []core.BackendStatus{}}
}
func (f *fakeCtl) Start(s string) error { f.started = s; return f.startErr }
func (f *fakeCtl) Stop()                { f.stopped++; f.started = "" }
func (f *fakeCtl) Switch(b string) error {
	f.switched = b
	if b == "nope" {
		return core.ErrUnknownBackend
	}
	return nil
}
func (f *fakeCtl) Test() string { return "test report\n" }
func (f *fakeCtl) Variants() []Variant {
	return []Variant{{"wg", "WireGuard", true}, {"masque", "MASQUE", false}}
}

func do(t *testing.T, h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1:8808"+path, nil)
	for k, v := range hdr {
		if k == "Host" {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRoutes(t *testing.T) {
	f := &fakeCtl{}
	h := Handler(Options{}, f)

	w := do(t, h, "/status", nil)
	var st map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &st) != nil || st["version"] != "9.9" {
		t.Fatalf("/status: %d %s", w.Code, w.Body)
	}
	for _, k := range []string{"version", "running", "run_mode", "variant", "last_mode", "port", "mode", "active", "bytes_up", "bytes_down", "backends"} {
		if _, ok := st[k]; !ok {
			t.Errorf("/status lacks the field %q", k)
		}
	}

	if w := do(t, h, "/start?mode=auto", nil); w.Code != 200 || f.started != "auto" {
		t.Errorf("/start: %d %q", w.Code, f.started)
	}
	if do(t, h, "/start?mode=warp&variant=masque-h2", nil); f.started != "warp@masque-h2" {
		t.Errorf("variant parameter: %q", f.started)
	}
	if do(t, h, "/start?mode=warp@gool&variant=masque", nil); f.started != "warp@gool" {
		t.Errorf("a variant inside mode must win: %q", f.started)
	}
	f.startErr = errors.New("cannot start: boom")
	if w := do(t, h, "/start?mode=tor", nil); w.Code != 400 {
		t.Errorf("a failed start: %d", w.Code)
	}
	if do(t, h, "/stop", nil); f.stopped != 1 {
		t.Error("/stop did not stop")
	}
	if w := do(t, h, "/switch?backend=tor", nil); w.Code != 200 || f.switched != "tor" {
		t.Errorf("/switch: %d %q", w.Code, f.switched)
	}
	if w := do(t, h, "/switch?backend=nope", nil); w.Code != 400 {
		t.Errorf("/switch unknown: %d", w.Code)
	}
	if w := do(t, h, "/test", nil); w.Code != 200 || w.Body.String() != "test report\n" {
		t.Errorf("/test: %d %q", w.Code, w.Body)
	}
	var vs []Variant
	w = do(t, h, "/variants", nil)
	if json.Unmarshal(w.Body.Bytes(), &vs) != nil || len(vs) != 2 || vs[1].Available {
		t.Errorf("/variants: %s", w.Body)
	}
	if w := do(t, h, "/nothing", nil); w.Code != 404 {
		t.Errorf("unknown route: %d", w.Code)
	}
}

func TestToken(t *testing.T) {
	h := Handler(Options{Token: "s3cret"}, &fakeCtl{})
	if w := do(t, h, "/status", nil); w.Code != 401 {
		t.Errorf("no token: %d", w.Code)
	}
	if w := do(t, h, "/status", map[string]string{"X-Token": "wrong"}); w.Code != 401 {
		t.Errorf("wrong token: %d", w.Code)
	}
	if w := do(t, h, "/status", map[string]string{"X-Token": "s3cret"}); w.Code != 200 {
		t.Errorf("right token: %d", w.Code)
	}
}

// The API is a set of GET requests on a local port, so a web page in the user's browser must
// not be able to start, stop or switch anything.
func TestBrowserPagesAreRefused(t *testing.T) {
	f := &fakeCtl{}
	h := Handler(Options{}, f)
	refused := map[string]map[string]string{
		"cross-site fetch":       {"Sec-Fetch-Site": "cross-site"},
		"same-site fetch":        {"Sec-Fetch-Site": "same-site"},
		"foreign origin":         {"Origin": "https://evil.example"},
		"opaque origin":          {"Origin": "null"},
		"DNS rebinding host":     {"Host": "evil.example:8808"},
		"rebinding host no port": {"Host": "attacker.test"},
		"LAN address as host":    {"Host": "192.168.1.5:8808"},
	}
	for name, hdr := range refused {
		if w := do(t, h, "/stop", hdr); w.Code != 403 {
			t.Errorf("%s: status %d, want 403", name, w.Code)
		}
	}
	if f.stopped != 0 {
		t.Errorf("a refused request still stopped the proxy (%d times)", f.stopped)
	}
	allowed := map[string]map[string]string{
		"an app (no browser headers)": nil,
		"same-origin page":            {"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8808"},
		"address bar":                 {"Sec-Fetch-Site": "none"},
		"localhost name":              {"Host": "localhost:8808"},
		"IPv6 loopback":               {"Host": "[::1]:8808"},
		"loopback origin":             {"Origin": "http://localhost:3000"},
	}
	for name, hdr := range allowed {
		if w := do(t, h, "/status", hdr); w.Code != 200 {
			t.Errorf("%s: status %d, want 200", name, w.Code)
		}
	}
}

func TestOffWhenPortIsNegative(t *testing.T) {
	Serve(nil, Options{Port: -1}, &fakeCtl{}) // must return without touching the (nil) context
}
