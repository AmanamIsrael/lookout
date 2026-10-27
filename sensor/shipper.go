package sensor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AmanamIsrael/lookout/event"
)

const (
	flushEvery    = 2 * time.Second
	flushAt       = 1000   // events per batch
	maxPending    = 50_000 // events held while the server is unreachable
	decisionsPoll = 5 * time.Second
)

// Shipper buffers events and uploads them to the server in gzip batches.
// Emit never blocks: when the buffer is full the event is counted and dropped,
// so a slow or dead server can't slow down proxied traffic.
type Shipper struct {
	server  string
	key     string
	client  *http.Client
	reqs    chan event.Request
	egress  chan event.Egress
	dropped atomic.Int64
}

func NewShipper(server, key string) *Shipper {
	return &Shipper{
		server: strings.TrimRight(server, "/"),
		key:    key,
		client: &http.Client{Timeout: 15 * time.Second},
		reqs:   make(chan event.Request, 8192),
		egress: make(chan event.Egress, 2048),
	}
}

func (s *Shipper) EmitRequest(ev event.Request) {
	select {
	case s.reqs <- ev:
	default:
		s.dropped.Add(1)
	}
}

func (s *Shipper) EmitEgress(ev event.Egress) {
	select {
	case s.egress <- ev:
	default:
		s.dropped.Add(1)
	}
}

// Run uploads batches until ctx is done, then makes one last attempt.
func (s *Shipper) Run(ctx context.Context) {
	var batch event.Batch
	tick := time.NewTicker(flushEvery)
	defer tick.Stop()
	backoff := time.Time{}

	flush := func(ctx context.Context) {
		size := len(batch.Requests) + len(batch.Egress)
		if size == 0 && s.dropped.Load() == 0 {
			return
		}
		batch.Dropped += int(s.dropped.Swap(0))
		if err := s.send(ctx, batch); err != nil {
			slog.Warn("ship failed; keeping batch", "events", size, "err", err)
			backoff = time.Now().Add(10 * time.Second)
			// Keep the newest events when the backlog is too big.
			if over := len(batch.Requests) - maxPending; over > 0 {
				batch.Requests = batch.Requests[over:]
				batch.Dropped += over
			}
			return
		}
		batch = event.Batch{}
	}

	for {
		select {
		case <-ctx.Done():
			drain(s.reqs, &batch.Requests)
			drain(s.egress, &batch.Egress)
			final, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			flush(final)
			cancel()
			return
		case ev := <-s.reqs:
			batch.Requests = append(batch.Requests, ev)
		case ev := <-s.egress:
			batch.Egress = append(batch.Egress, ev)
		case <-tick.C:
			if time.Now().After(backoff) {
				flush(ctx)
			}
			continue
		}
		if len(batch.Requests)+len(batch.Egress) >= flushAt && time.Now().After(backoff) {
			flush(ctx)
		}
	}
}

func drain[T any](ch chan T, into *[]T) {
	for {
		select {
		case v := <-ch:
			*into = append(*into, v)
		default:
			return
		}
	}
}

func (s *Shipper) send(ctx context.Context, b event.Batch) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server+"/v1/ingest", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("ingest: %s", resp.Status)
	}
	return nil
}

// PollDecisions keeps e in sync with the server's active decisions.
func (s *Shipper) PollDecisions(ctx context.Context, e *Enforcer) {
	etag := ""
	for {
		next, err := s.fetchDecisions(ctx, e, etag)
		if err != nil {
			slog.Warn("decision sync failed", "err", err)
		} else {
			etag = next
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(decisionsPoll):
		}
	}
}

func (s *Shipper) fetchDecisions(ctx context.Context, e *Enforcer, etag string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.server+"/v1/decisions", nil)
	if err != nil {
		return etag, err
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return etag, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return etag, nil
	case http.StatusOK:
		var body event.Decisions
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&body); err != nil {
			return etag, err
		}
		e.Replace(body.Decisions)
		slog.Info("decisions synced", "active", len(body.Decisions))
		return resp.Header.Get("ETag"), nil
	default:
		return etag, fmt.Errorf("decisions: %s", resp.Status)
	}
}
