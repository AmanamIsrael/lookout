package server_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server"
	"github.com/AmanamIsrael/lookout/server/store"
	"github.com/AmanamIsrael/lookout/server/verify"
)

const adminToken = "test-admin-token-0123456789"

type noDNS struct{}

func (noDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}
func (noDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return nil, nil }

type rig struct {
	st     *store.Store
	engine *server.Engine
	srv    *httptest.Server
	admin  *http.Client
	key    string
}

func newRig(t *testing.T) *rig {
	st, err := store.Open(filepath.Join(t.TempDir(), "lookout.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := server.NewEngine(server.DefaultConfig(), st, verify.New(verify.NewWebBotAuth(nil), noDNS{}), nil)
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>lookout</title>")}}
	srv := httptest.NewServer(server.NewAPI(st, eng, adminToken, ui).Handler())
	t.Cleanup(srv.Close)
	_, key, err := st.CreateSensor(context.Background(), "web-1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	return &rig{st: st, engine: eng, srv: srv, admin: &http.Client{Jar: jar}, key: key}
}

func (rg *rig) ingest(t *testing.T, key string, b event.Batch) int {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	json.NewEncoder(zw).Encode(b)
	zw.Close()
	req, _ := http.NewRequest("POST", rg.srv.URL+"/v1/ingest", &buf)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (rg *rig) call(t *testing.T, method, path string, body any, out any) int {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, rg.srv.URL+path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", rg.srv.URL)
	}
	resp, err := rg.admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func scannerBatch() event.Batch {
	var b event.Batch
	for i, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/actuator/env", "/server-status", "/backup.sql", "/config.json"} {
		b.Requests = append(b.Requests, event.Request{
			TS: time.Now().Add(time.Duration(i-10) * time.Second), IP: "203.0.113.50", Method: "GET",
			Host: "example.com", Path: p, Proto: "HTTP/1.1", Status: 404, UA: "zgrab/0.x", Action: event.ActionAllow,
		})
	}
	return b
}

func TestIngestRejectsBadKeys(t *testing.T) {
	rg := newRig(t)
	if code := rg.ingest(t, "lk_wrong", scannerBatch()); code != 401 {
		t.Fatalf("status %d", code)
	}
	if code := rg.ingest(t, "", scannerBatch()); code != 401 {
		t.Fatalf("status %d", code)
	}
}

func TestAdminNeedsLogin(t *testing.T) {
	rg := newRig(t)
	if code := rg.call(t, "GET", "/api/actors", nil, nil); code != 401 {
		t.Fatalf("status %d", code)
	}
	if code := rg.call(t, "POST", "/api/login", map[string]string{"token": "nope"}, nil); code != 401 {
		t.Fatalf("wrong token: status %d", code)
	}
	if code := rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil); code != 200 {
		t.Fatalf("login: status %d", code)
	}
	if code := rg.call(t, "GET", "/api/actors", nil, nil); code != 200 {
		t.Fatalf("after login: status %d", code)
	}
}

func TestCrossSiteWriteIsRefused(t *testing.T) {
	rg := newRig(t)
	rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil)
	b, _ := json.Marshal(map[string]string{"name": "x"})
	req, _ := http.NewRequest("POST", rg.srv.URL+"/api/sensors", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, _ := rg.admin.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// The whole loop without an LLM: a scanner's traffic is scored by the rules,
// a block is suggested, a human approves it and sensors receive it.
func TestScannerToEnforcedDecision(t *testing.T) {
	rg := newRig(t)
	ctx := context.Background()
	if code := rg.ingest(t, rg.key, scannerBatch()); code != 202 {
		t.Fatalf("ingest status %d", code)
	}
	if err := rg.engine.AnalyzeOnce(ctx); err != nil {
		t.Fatal(err)
	}

	rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil)
	var actors []store.Actor
	rg.call(t, "GET", "/api/actors?filter=suspicious", nil, &actors)
	if len(actors) != 1 || actors[0].IP != "203.0.113.50" || actors[0].Class != "scanner" || actors[0].Risk < 80 {
		t.Fatalf("actors %+v", actors)
	}
	var overview struct{ Stats store.Overview }
	rg.call(t, "GET", "/api/overview", nil, &overview)
	if b := overview.Stats.Bands; b != (store.RiskBands{Hostile: 1}) || overview.Stats.PendingDecisions != 1 {
		t.Fatalf("overview %+v", overview.Stats)
	}

	var decisions []store.Decision
	rg.call(t, "GET", "/api/decisions", nil, &decisions)
	if len(decisions) != 1 || decisions[0].Status != store.StatusPending || decisions[0].Kind != event.KindBlock || decisions[0].Source != "rules" ||
		decisions[0].Actor == nil || decisions[0].Actor.Class != "scanner" {
		t.Fatalf("decisions %+v", decisions)
	}

	// Not enforced until approved.
	var feed event.Decisions
	sensorGet(t, rg, "", &feed)
	if len(feed.Decisions) != 0 {
		t.Fatalf("pending decision reached sensors: %+v", feed)
	}

	var approved store.Decision
	if code := rg.call(t, "POST", fmt.Sprintf("/api/decisions/%d/approve", decisions[0].ID), map[string]any{}, &approved); code != 200 {
		t.Fatalf("approve status %d", code)
	}
	if approved.Status != store.StatusActive || approved.ExpiresAt == nil {
		t.Fatalf("approved %+v", approved)
	}
	// Approving twice is a conflict, not a second TTL.
	if code := rg.call(t, "POST", fmt.Sprintf("/api/decisions/%d/approve", decisions[0].ID), map[string]any{}, nil); code != 409 {
		t.Fatalf("double approve status %d", code)
	}

	etag := sensorGet(t, rg, "", &feed)
	if len(feed.Decisions) != 1 || feed.Decisions[0].IP != "203.0.113.50" || feed.Decisions[0].Kind != event.KindBlock {
		t.Fatalf("feed %+v", feed)
	}
	if code := sensorStatus(t, rg, etag); code != 304 {
		t.Fatalf("unchanged feed: status %d", code)
	}

	// More traffic from the same scanner doesn't stack a second suggestion.
	rg.ingest(t, rg.key, scannerBatch())
	rg.engine.AnalyzeOnce(ctx)
	rg.call(t, "GET", "/api/decisions", nil, &decisions)
	if len(decisions) != 1 {
		t.Fatalf("duplicate suggestion: %d decisions", len(decisions))
	}

	// Revoking takes it off the feed.
	rg.call(t, "POST", fmt.Sprintf("/api/decisions/%d/revoke", approved.ID), map[string]any{}, nil)
	sensorGet(t, rg, "", &feed)
	if len(feed.Decisions) != 0 {
		t.Fatalf("revoked decision still enforced: %+v", feed)
	}
}

func TestRejectedSuggestionIsNotRepeated(t *testing.T) {
	rg := newRig(t)
	ctx := context.Background()
	rg.ingest(t, rg.key, scannerBatch())
	rg.engine.AnalyzeOnce(ctx)
	rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil)
	var decisions []store.Decision
	rg.call(t, "GET", "/api/decisions", nil, &decisions)
	rg.call(t, "POST", fmt.Sprintf("/api/decisions/%d/reject", decisions[0].ID), map[string]any{}, nil)

	rg.ingest(t, rg.key, scannerBatch())
	rg.engine.AnalyzeOnce(ctx)
	rg.call(t, "GET", "/api/decisions", nil, &decisions)
	if len(decisions) != 1 || decisions[0].Status != store.StatusRejected {
		t.Fatalf("decisions %+v", decisions)
	}
}

func TestIngestSanitizesHostileFields(t *testing.T) {
	rg := newRig(t)
	b := event.Batch{Requests: []event.Request{
		{TS: time.Now(), IP: "not-an-ip", Method: "GET", Path: "/"},
		{TS: time.Now().Add(240 * time.Hour), IP: "::ffff:198.51.100.1", Method: "GET", Path: "/" + strings.Repeat("a", 10_000),
			Action: "pwn", Hints: map[string]string{"x-evil": "1", "accept": "text/html"}},
	}}
	if code := rg.ingest(t, rg.key, b); code != 202 {
		t.Fatalf("status %d", code)
	}
	rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil)
	var actors []store.Actor
	rg.call(t, "GET", "/api/actors?filter=all", nil, &actors)
	if len(actors) != 1 || actors[0].IP != "198.51.100.1" {
		t.Fatalf("actors %+v", actors)
	}
	var detail struct {
		Requests []event.Request `json:"requests"`
	}
	rg.call(t, "GET", fmt.Sprintf("/api/actors/%d", actors[0].ID), nil, &detail)
	r := detail.Requests[0]
	if len(r.Path) != 2048 || r.Action != event.ActionAllow || r.Hints["x-evil"] != "" || r.TS.After(time.Now().Add(time.Minute)) {
		t.Fatalf("request not sanitized: path=%d action=%s hints=%v ts=%s", len(r.Path), r.Action, r.Hints, r.TS)
	}
}

func TestDecisionPollIsAHeartbeat(t *testing.T) {
	rg := newRig(t)
	rg.call(t, "POST", "/api/login", map[string]string{"token": adminToken}, nil)
	var sensors []store.Sensor
	rg.call(t, "GET", "/api/sensors", nil, &sensors)
	if len(sensors) != 1 || sensors[0].LastSeenAt != nil {
		t.Fatalf("before poll: %+v", sensors)
	}
	// A quiet sensor ships no events but still polls; it must not look offline.
	sensorGet(t, rg, "", &event.Decisions{})
	rg.call(t, "GET", "/api/sensors", nil, &sensors)
	if sensors[0].LastSeenAt == nil || time.Since(*sensors[0].LastSeenAt) > time.Minute {
		t.Fatalf("after poll: %+v", sensors)
	}
}

func sensorGet(t *testing.T, rg *rig, etag string, out *event.Decisions) string {
	req, _ := http.NewRequest("GET", rg.srv.URL+"/v1/decisions", nil)
	req.Header.Set("Authorization", "Bearer "+rg.key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	*out = event.Decisions{}
	json.NewDecoder(resp.Body).Decode(out)
	return resp.Header.Get("ETag")
}

func sensorStatus(t *testing.T, rg *rig, etag string) int {
	req, _ := http.NewRequest("GET", rg.srv.URL+"/v1/decisions", nil)
	req.Header.Set("Authorization", "Bearer "+rg.key)
	req.Header.Set("If-None-Match", etag)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
