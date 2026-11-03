package core

import "errors"

// Sentinel errors. Test for them with errors.Is; the texts are what users see in the log.
var (
	// ErrNotReady: the backend is not connected (yet, or any more).
	ErrNotReady = errors.New("backend is not ready")
	// ErrNoBackend: no backend is ready, so there is nothing to dial through.
	ErrNoBackend = errors.New("no backend is ready yet")
	// ErrNoUDPBackend: backends are ready but none of them can carry UDP.
	ErrNoUDPBackend = errors.New("no UDP-capable backend is ready")
	// ErrUDPUnsupported: this backend cannot carry UDP.
	ErrUDPUnsupported = errors.New("UDP is not supported by this backend")
	// ErrUnknownBackend: a backend name that the running mode does not have.
	ErrUnknownBackend = errors.New("unknown backend")
)

type wrapped struct {
	msg string
	err error
}

func (e *wrapped) Error() string { return e.msg }
func (e *wrapped) Unwrap() error { return e.err }

// Wrap makes an error that prints as msg and matches sentinel under errors.Is. It lets a
// backend keep its own wording ("psiphon not connected") while callers still test the kind.
func Wrap(sentinel error, msg string) error { return &wrapped{msg: msg, err: sentinel} }

// NotReady is Wrap(ErrNotReady, msg).
func NotReady(msg string) error { return Wrap(ErrNotReady, msg) }

// NoUDP is Wrap(ErrUDPUnsupported, msg).
func NoUDP(msg string) error { return Wrap(ErrUDPUnsupported, msg) }
