// Package verify proves (or disproves) who an actor says it is: Web Bot Auth
// signatures for AI agents, forward-confirmed reverse DNS for crawlers.
package verify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server/analyze"
)

const rdnsTTL = 6 * time.Hour

// Resolver is the DNS subset Verifier uses; *net.Resolver satisfies it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type Verifier struct {
	wba      *WebBotAuth
	resolver Resolver
	mu       sync.Mutex
	rdns     map[string]rdnsResult
}

type rdnsResult struct {
	id analyze.Identity
	at time.Time
}

func New(wba *WebBotAuth, resolver Resolver) *Verifier {
	return &Verifier{wba: wba, resolver: resolver, rdns: map[string]rdnsResult{}}
}

// Identify checks the actor's newest signed request, then its declared
// crawler identity. A zero Identity means nothing was claimed, or the check
// could not run (e.g. DNS timeout) and should not count against the actor.
func (v *Verifier) Identify(ctx context.Context, reqs []event.Request) analyze.Identity {
	for i := len(reqs) - 1; i >= 0; i-- {
		r := reqs[i]
		if r.Hints["signature-input"] == "" {
			continue
		}
		origin, err := v.wba.Verify(ctx, r)
		switch {
		case err == nil:
			return analyze.Identity{Verified: strings.TrimPrefix(origin, "https://") + " (Web Bot Auth signature)"}
		case errors.Is(err, ErrNoSignature):
			continue
		case errors.Is(err, ErrDirectoryUnavailable):
			return analyze.Identity{} // can't tell; don't count it against the actor
		default:
			return analyze.Identity{Failed: "Web Bot Auth signature failed: " + err.Error()}
		}
	}
	if len(reqs) == 0 {
		return analyze.Identity{}
	}
	last := reqs[len(reqs)-1]
	agent, ok := analyze.ClaimedAgent(last.UA)
	if !ok || len(agent.RDNS) == 0 {
		return analyze.Identity{}
	}
	return v.reverseDNS(ctx, last.IP, agent)
}

// reverseDNS does forward-confirmed reverse DNS, the check Google, Microsoft,
// Apple and others document for their crawlers.
func (v *Verifier) reverseDNS(ctx context.Context, ip string, agent analyze.Agent) analyze.Identity {
	key := ip + "|" + agent.Token
	v.mu.Lock()
	if c, ok := v.rdns[key]; ok && time.Since(c.at) < rdnsTTL {
		v.mu.Unlock()
		return c.id
	}
	v.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, cacheable := v.lookup(ctx, ip, agent)
	if cacheable {
		v.mu.Lock()
		v.rdns[key] = rdnsResult{id: id, at: time.Now()}
		v.mu.Unlock()
	}
	return id
}

func (v *Verifier) lookup(ctx context.Context, ip string, agent analyze.Agent) (analyze.Identity, bool) {
	names, err := v.resolver.LookupAddr(ctx, ip)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return analyze.Identity{}, false // transient; try again next time
	}
	want := strings.Join(agent.RDNS, " or ")
	if len(names) == 0 {
		return analyze.Identity{Failed: fmt.Sprintf("Claims to be %s (%s) but %s has no reverse DNS; real %s IPs resolve to %s",
			agent.Token, agent.Operator, ip, agent.Token, want)}, true
	}
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !slices.ContainsFunc(agent.RDNS, func(d string) bool { return host == d || strings.HasSuffix(host, "."+d) }) {
			continue
		}
		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return analyze.Identity{}, false
		}
		for _, a := range addrs {
			if a.IP.String() == ip {
				return analyze.Identity{Verified: fmt.Sprintf("%s via reverse DNS (%s)", agent.Token, host)}, true
			}
		}
	}
	return analyze.Identity{Failed: fmt.Sprintf("Claims to be %s (%s) but %s resolves to %s, not %s",
		agent.Token, agent.Operator, ip, strings.TrimSuffix(names[0], "."), want)}, true
}
