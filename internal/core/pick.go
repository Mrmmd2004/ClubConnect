package core

import "time"

// Candidate is what Pick needs to know about one backend.
type Candidate struct {
	Healthy bool
	Latency time.Duration
}

// The current backend is kept as long as it is healthy and not slower than 1.4 times the best
// one: without this margin two engines of similar speed would be swapped back and forth.
const (
	hysteresisNum = 14
	hysteresisDen = 10
)

// Pick chooses which backend should be active. cur is the index in use now (-1 = none yet).
// It returns the index to use and ok=true; when no backend is healthy it returns cur, false
// and the caller keeps what it has. Ties go to the earlier backend (the one higher in the
// configured order).
func Pick(cs []Candidate, cur int) (next int, ok bool) {
	best := -1
	var bestLat time.Duration
	for i, c := range cs {
		if c.Healthy && (best < 0 || c.Latency < bestLat) {
			best, bestLat = i, c.Latency
		}
	}
	if best < 0 {
		return cur, false
	}
	if cur >= 0 && cur < len(cs) && cur != best {
		if c := cs[cur]; c.Healthy && c.Latency <= bestLat*hysteresisNum/hysteresisDen {
			return cur, true // hysteresis: avoid flapping
		}
	}
	return best, true
}
