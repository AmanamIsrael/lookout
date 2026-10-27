package sensor

import (
	"sync"
	"time"

	"github.com/AmanamIsrael/lookout/event"
)

// Enforcer holds the active decisions pulled from the server and answers,
// per request, which one applies. Lookups are a map hit on the client IP.
type Enforcer struct {
	mu      sync.RWMutex
	byIP    map[string][]event.Decision
	buckets map[bucketKey]*bucket
}

type bucketKey struct {
	decision int64
	ip       string
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewEnforcer() *Enforcer {
	return &Enforcer{byIP: map[string][]event.Decision{}, buckets: map[bucketKey]*bucket{}}
}

// Replace swaps the full decision set.
func (e *Enforcer) Replace(ds []event.Decision) {
	byIP := make(map[string][]event.Decision, len(ds))
	live := make(map[int64]bool, len(ds))
	for _, d := range ds {
		byIP[d.IP] = append(byIP[d.IP], d)
		live[d.ID] = true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.byIP = byIP
	for k := range e.buckets {
		if !live[k.decision] {
			delete(e.buckets, k)
		}
	}
}

// Match returns the strictest unexpired decision for ip/ja4, if any.
// Block beats challenge beats rate limit.
func (e *Enforcer) Match(ip, ja4 string, now time.Time) (event.Decision, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var best event.Decision
	found := false
	for _, d := range e.byIP[ip] {
		if now.After(d.ExpiresAt) || (d.JA4 != "" && d.JA4 != ja4) {
			continue
		}
		if !found || severity(d.Kind) > severity(best.Kind) {
			best, found = d, true
		}
	}
	return best, found
}

func severity(k event.DecisionKind) int {
	switch k {
	case event.KindBlock:
		return 3
	case event.KindChallenge:
		return 2
	case event.KindRateLimit:
		return 1
	}
	return 0
}

// Allow spends one token from the decision's per-IP bucket. The bucket holds
// one minute of requests and refills at RPM per minute.
func (e *Enforcer) Allow(d event.Decision, ip string, now time.Time) bool {
	rpm := float64(max(d.RPM, 1))
	e.mu.Lock()
	defer e.mu.Unlock()
	k := bucketKey{d.ID, ip}
	b, ok := e.buckets[k]
	if !ok {
		b = &bucket{tokens: rpm, last: now}
		e.buckets[k] = b
	}
	b.tokens = min(rpm, b.tokens+now.Sub(b.last).Minutes()*rpm)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
