package proc

import (
	"net"
	"strconv"
	"sync"
)

// PortAllocator hands out local ports for the helper programs. It prefers a range (Club Connect
// uses 8801-8899) and falls back to any free port. A port it handed out is not given to anybody
// else until Release, because a helper needs a moment before it has bound the port.
type PortAllocator struct {
	Lo, Hi int

	mu   sync.Mutex
	used map[int]bool
}

// NewPortAllocator makes an allocator that prefers lo..hi.
func NewPortAllocator(lo, hi int) *PortAllocator { return &PortAllocator{Lo: lo, Hi: hi} }

// Ports is the allocator Club Connect uses: the 88xx range.
var Ports = NewPortAllocator(8801, 8899)

func (a *PortAllocator) claim(p int) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used == nil {
		a.used = map[int]bool{}
	}
	if a.used[p] {
		return false
	}
	a.used[p] = true
	return true
}

// Release gives a port back (call it when the helper that used it has stopped).
func (a *PortAllocator) Release(p int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, p)
}

// Free returns a free loopback TCP port, or 0 when none can be found.
func (a *PortAllocator) Free() int {
	for p := a.Lo; p <= a.Hi; p++ {
		if l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p))); err == nil {
			l.Close()
			if !a.claim(p) {
				continue
			}
			return p
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// FreePort is Ports.Free().
func FreePort() int { return Ports.Free() }

// ReleasePort is Ports.Release.
func ReleasePort(p int) { Ports.Release(p) }
