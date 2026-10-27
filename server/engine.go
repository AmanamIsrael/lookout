// Package server is lookout's collector: it ingests sensor batches, scores
// actors, asks the LLM about the interesting ones, turns verdicts into
// suggested decisions and serves the dashboard.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server/analyze"
	"github.com/AmanamIsrael/lookout/server/store"
	"github.com/AmanamIsrael/lookout/server/triage"
	"github.com/AmanamIsrael/lookout/server/verify"
)

// Config tunes the engine.
type Config struct {
	// Window is how much of an actor's history the rules and LLM look at.
	Window time.Duration
	// TriageMinScore is the rule score that earns an actor an LLM look.
	TriageMinScore int
	// TriagePerHour caps LLM calls so a flood of actors can't run up a bill.
	TriagePerHour int
	// Retention is how long requests are kept.
	Retention time.Duration
}

func DefaultConfig() Config {
	return Config{Window: 24 * time.Hour, TriageMinScore: 25, TriagePerHour: 120, Retention: 7 * 24 * time.Hour}
}

type Engine struct {
	cfg      Config
	store    *store.Store
	verifier *verify.Verifier
	triager  *triage.Triager // nil when no API key is configured

	mu      sync.Mutex
	calls   []time.Time // LLM calls in the last hour
	running map[int64]bool
}

func NewEngine(cfg Config, st *store.Store, v *verify.Verifier, t *triage.Triager) *Engine {
	return &Engine{cfg: cfg, store: st, verifier: v, triager: t, running: map[int64]bool{}}
}

// LLM returns the triage model, or "" when triage is off.
func (e *Engine) LLM() string {
	if e.triager == nil {
		return ""
	}
	return e.triager.Model()
}

// Run drives the background loops until ctx is done.
func (e *Engine) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { every(ctx, 5*time.Second, e.AnalyzeOnce) })
	if e.triager != nil {
		wg.Go(func() { every(ctx, 10*time.Second, e.TriageOnce) })
	}
	wg.Go(func() {
		every(ctx, time.Hour, func(ctx context.Context) error {
			return e.store.Prune(ctx, time.Now().Add(-e.cfg.Retention))
		})
	})
	wg.Wait()
}

func every(ctx context.Context, d time.Duration, fn func(context.Context) error) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			slog.Error("background job failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// AnalyzeOnce scores every actor with new requests.
func (e *Engine) AnalyzeOnce(ctx context.Context) error {
	actors, err := e.store.ActorsToAnalyze(ctx, 500)
	if err != nil {
		return err
	}
	for _, a := range actors {
		if err := e.analyze(ctx, a); err != nil {
			return fmt.Errorf("analyze actor %d: %w", a.ID, err)
		}
	}
	return nil
}

func (e *Engine) analyze(ctx context.Context, a store.Actor) error {
	now := time.Now()
	reqs, err := e.store.ActorRequests(ctx, a.ID, now.Add(-e.cfg.Window), 2000)
	if err != nil {
		return err
	}
	id := e.verifier.Identify(ctx, reqs)
	res := analyze.Analyze(reqs, id)
	verified := id.Verified
	if err := e.store.SaveAnalysis(ctx, a.ID, res.Score, res.Class, res.Signals, verified, a.LastSeen); err != nil {
		return err
	}
	if e.triager == nil {
		return e.suggestFromRules(ctx, a, res, now)
	}
	return nil
}

// suggestFromRules is the decision layer when no LLM is configured: only
// high scores produce a suggestion, sized to the class.
func (e *Engine) suggestFromRules(ctx context.Context, a store.Actor, res analyze.Result, now time.Time) error {
	if res.Score < 80 || a.DismissedAt != nil {
		return nil
	}
	d := store.Decision{ActorID: &a.ID, IP: a.IP, Source: "rules", Status: store.StatusPending}
	switch res.Class {
	case analyze.ClassScanner, analyze.ClassImpersonator:
		d.Kind, d.TTLMinutes = event.KindBlock, 24*60
	case analyze.ClassAutomation, analyze.ClassAIAgent:
		d.Kind, d.TTLMinutes, d.JA4 = event.KindChallenge, 6*60, a.JA4
	default:
		d.Kind, d.TTLMinutes, d.RPM = event.KindRateLimit, 60, 60
	}
	var reasons []string
	for _, s := range res.Signals[:min(3, len(res.Signals))] {
		reasons = append(reasons, s.Detail)
	}
	d.Reason = fmt.Sprintf("Rule score %d (%s): %s", res.Score, res.Class, strings.Join(reasons, "; "))
	return e.suggest(ctx, d, now)
}

func (e *Engine) suggest(ctx context.Context, d store.Decision, now time.Time) error {
	open, err := e.store.HasOpenDecision(ctx, *d.ActorID, now)
	if err != nil || open {
		return err
	}
	_, err = e.store.CreateDecision(ctx, d, now)
	if err == nil {
		slog.Info("decision suggested", "actor", *d.ActorID, "kind", d.Kind, "source", d.Source)
	}
	return err
}

// TriageOnce sends waiting actors to the LLM, within the hourly budget.
func (e *Engine) TriageOnce(ctx context.Context) error {
	budget := e.budget()
	if budget == 0 {
		return nil
	}
	actors, err := e.store.ActorsToTriage(ctx, e.cfg.TriageMinScore, min(budget, 4))
	if err != nil {
		return err
	}
	for _, a := range actors {
		if _, err := e.Triage(ctx, a.ID); err != nil {
			slog.Warn("triage failed", "actor", a.ID, "err", err)
		}
	}
	return nil
}

func (e *Engine) budget() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := time.Now().Add(-time.Hour)
	i := 0
	for i < len(e.calls) && e.calls[i].Before(cutoff) {
		i++
	}
	e.calls = e.calls[i:]
	return max(0, e.cfg.TriagePerHour-len(e.calls))
}

var (
	ErrTriageOff  = errors.New("LLM triage is not configured")
	ErrTriageBusy = errors.New("triage already running for this actor")
)

// Triage runs the LLM on one actor now and stores the verdict.
func (e *Engine) Triage(ctx context.Context, actorID int64) (triage.Verdict, error) {
	if e.triager == nil {
		return triage.Verdict{}, ErrTriageOff
	}
	e.mu.Lock()
	if e.running[actorID] {
		e.mu.Unlock()
		return triage.Verdict{}, ErrTriageBusy
	}
	e.running[actorID] = true
	e.calls = append(e.calls, time.Now())
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, actorID)
		e.mu.Unlock()
	}()

	a, err := e.store.Actor(ctx, actorID)
	if err != nil {
		return triage.Verdict{}, err
	}
	now := time.Now()
	reqs, err := e.store.ActorRequests(ctx, a.ID, now.Add(-e.cfg.Window), 2000)
	if err != nil {
		return triage.Verdict{}, err
	}
	id := e.verifier.Identify(ctx, reqs)
	rules := analyze.Analyze(reqs, id)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	v, err := e.triager.Triage(ctx, triage.Input{IP: a.IP, JA4: a.JA4, Identity: id, Rules: rules, Requests: reqs})
	if err != nil {
		return v, err
	}
	if err := e.store.SaveTriage(ctx, a.ID, v, v.Risk, a.Requests, now); err != nil {
		return v, err
	}
	slog.Info("actor triaged", "actor", a.ID, "class", v.Classification, "risk", v.Risk, "action", v.Action)

	switch v.Action {
	case "rate_limit", "challenge", "block":
	default:
		return v, nil
	}
	if v.Risk < 50 || a.DismissedAt != nil {
		return v, nil
	}
	d := store.Decision{
		ActorID: &a.ID, IP: a.IP, Kind: event.DecisionKind(v.Action), TTLMinutes: v.TTLMinutes,
		Reason: v.Summary, Source: "llm", Status: store.StatusPending,
	}
	if v.Scope == "fingerprint" {
		d.JA4 = a.JA4
	}
	if d.Kind == event.KindRateLimit {
		d.RPM = 60
	}
	return v, e.suggest(ctx, d, now)
}
