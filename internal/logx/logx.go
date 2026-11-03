// Package logx is Club Connect's logging layer: log/slog underneath, and a plain handler on top
// that prints exactly what the old log package printed ("15:04:05 [component] message"), so the
// console looks the same as before while every line is now a structured slog record.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Init makes the plain handler the default slog handler (and routes the standard log package
// through it).
func Init() { InitWriter(os.Stderr, slog.LevelInfo) }

// InitWriter is Init with a chosen writer and minimum level (used by tests).
func InitWriter(w io.Writer, level slog.Level) {
	slog.SetDefault(slog.New(NewPlainHandler(w, level)))
}

// Logger is a component logger: For("warp") prints lines starting with "[warp]".
type Logger struct{ name string }

// For returns the logger of one component. The empty name prints no prefix.
func For(name string) Logger { return Logger{name} }

func (l Logger) emit(level slog.Level, msg string, args ...any) {
	lg := slog.Default()
	if !lg.Enabled(context.Background(), level) {
		return
	}
	if l.name != "" {
		lg = lg.With("c", l.name)
	}
	lg.Log(context.Background(), level, msg, args...)
}

// Info logs a message with optional key/value attributes (printed as " key=value").
func (l Logger) Info(msg string, args ...any) { l.emit(slog.LevelInfo, msg, args...) }

// Warn and Error print like Info (the console never showed levels) but carry their level for
// any other slog handler.
func (l Logger) Warn(msg string, args ...any)  { l.emit(slog.LevelWarn, msg, args...) }
func (l Logger) Error(msg string, args ...any) { l.emit(slog.LevelError, msg, args...) }

// Infof, Warnf and Errorf are the printf forms used where a line must read exactly as before.
func (l Logger) Infof(format string, a ...any)  { l.emit(slog.LevelInfo, fmt.Sprintf(format, a...)) }
func (l Logger) Warnf(format string, a ...any)  { l.emit(slog.LevelWarn, fmt.Sprintf(format, a...)) }
func (l Logger) Errorf(format string, a ...any) { l.emit(slog.LevelError, fmt.Sprintf(format, a...)) }

// PlainHandler writes "15:04:05 [c] message key=value".
type PlainHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Leveler
	comp  string
	attrs []slog.Attr
}

func NewPlainHandler(w io.Writer, level slog.Leveler) *PlainHandler {
	return &PlainHandler{mu: &sync.Mutex{}, w: w, level: level}
}

func (h *PlainHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func (h *PlainHandler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append([]slog.Attr(nil), h.attrs...)
	for _, a := range as {
		if a.Key == "c" {
			n.comp = a.Value.String()
			continue
		}
		n.attrs = append(n.attrs, a)
	}
	return &n
}

// WithGroup is accepted and ignored: the console format has no groups.
func (h *PlainHandler) WithGroup(string) slog.Handler { return h }

func (h *PlainHandler) Handle(_ context.Context, r slog.Record) error {
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	var sb strings.Builder
	sb.WriteString(t.Format("15:04:05"))
	sb.WriteByte(' ')
	comp := h.comp
	extra := append([]slog.Attr(nil), h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "c" {
			comp = a.Value.String()
		} else {
			extra = append(extra, a)
		}
		return true
	})
	if comp != "" {
		sb.WriteString("[" + comp + "] ")
	}
	sb.WriteString(r.Message)
	for _, a := range extra {
		v := a.Value.String()
		if strings.ContainsAny(v, " \t\"") {
			v = fmt.Sprintf("%q", v)
		}
		sb.WriteString(" " + a.Key + "=" + v)
	}
	sb.WriteByte('\n')
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, sb.String())
	return err
}
