package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server/store"
)

const (
	sessionCookie = "lookout_session"
	sessionTTL    = 7 * 24 * time.Hour
	maxBatchBytes = 16 << 20 // compressed
	maxBatchJSON  = 64 << 20 // decompressed
	maxBatchItems = 20_000
)

// API serves sensors (/v1) and the dashboard (/api and the UI).
type API struct {
	store      *store.Store
	engine     *Engine
	adminToken string
	sessionKey []byte
	ui         fs.FS
	logins     *limiter
	ingests    *limiter
}

// NewAPI wires the handlers. ui holds the built dashboard (index.html at its root).
func NewAPI(st *store.Store, eng *Engine, adminToken string, ui fs.FS) *API {
	k := hmac.New(sha256.New, []byte(adminToken))
	k.Write([]byte("lookout-session-v1"))
	return &API{
		store:      st,
		engine:     eng,
		adminToken: adminToken,
		sessionKey: k.Sum(nil), // rotating the admin token logs everyone out
		ui:         ui,
		logins:     newLimiter(10, time.Minute),
		ingests:    newLimiter(20, time.Second),
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// Sensors
	mux.HandleFunc("POST /v1/ingest", a.sensor(a.ingest))
	mux.HandleFunc("GET /v1/decisions", a.sensor(a.sensorDecisions))

	// Dashboard session
	mux.HandleFunc("GET /api/session", a.session)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)

	// Dashboard data
	mux.HandleFunc("GET /api/overview", a.admin(a.overview))
	mux.HandleFunc("GET /api/actors", a.admin(a.actors))
	mux.HandleFunc("GET /api/actors/{id}", a.admin(a.actor))
	mux.HandleFunc("POST /api/actors/{id}/triage", a.admin(a.triageActor))
	mux.HandleFunc("POST /api/actors/{id}/dismiss", a.admin(a.dismissActor))
	mux.HandleFunc("GET /api/decisions", a.admin(a.decisions))
	mux.HandleFunc("POST /api/decisions", a.admin(a.createDecision))
	mux.HandleFunc("POST /api/decisions/{id}/{verb}", a.admin(a.transition))
	mux.HandleFunc("GET /api/egress", a.admin(a.egress))
	mux.HandleFunc("GET /api/sensors", a.admin(a.sensors))
	mux.HandleFunc("POST /api/sensors", a.admin(a.createSensor))
	mux.HandleFunc("DELETE /api/sensors/{id}", a.admin(a.deleteSensor))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, http.StatusNotFound, "not found") })

	mux.Handle("/", a.static())
	return securityHeaders(mux)
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fail answers with a generic message; details go to the log, not the client.
func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "path", r.URL.Path, "err", err)
	fail(w, http.StatusInternalServerError, "internal error")
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, http.StatusUnsupportedMediaType, "expected application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		fail(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func queryHours(r *http.Request, def int) time.Time {
	h, err := strconv.Atoi(r.URL.Query().Get("hours"))
	if err != nil || h <= 0 || h > 24*30 {
		h = def
	}
	return time.Now().Add(-time.Duration(h) * time.Hour)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// limiter is a per-key token bucket.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*tokens
}

type tokens struct {
	n    float64
	last time.Time
}

func newLimiter(burst int, per time.Duration) *limiter {
	return &limiter{rate: float64(burst) / per.Seconds(), burst: float64(burst), buckets: map[string]*tokens{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.buckets) > 10_000 { // forget idle keys
		for k, b := range l.buckets {
			if now.Sub(b.last) > time.Hour {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &tokens{n: l.burst, last: now}
		l.buckets[key] = b
	}
	b.n = min(l.burst, b.n+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.n < 1 {
		return false
	}
	b.n--
	return true
}

// ---- sensors (/v1) ----------------------------------------------------------

type sensorHandler func(w http.ResponseWriter, r *http.Request, sensorID int64)

func (a *API) sensor(next sensorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !strings.HasPrefix(key, "lk_") {
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id, err := a.store.SensorIDByKey(r.Context(), key)
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		} else if err != nil {
			internal(w, r, err)
			return
		}
		if !a.ingests.allow(strconv.FormatInt(id, 10)) {
			fail(w, http.StatusTooManyRequests, "slow down")
			return
		}
		next(w, r, id)
	}
}

func (a *API) ingest(w http.ResponseWriter, r *http.Request, sensorID int64) {
	var body io.Reader = http.MaxBytesReader(w, r.Body, maxBatchBytes)
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(body)
		if err != nil {
			fail(w, http.StatusBadRequest, "invalid gzip")
			return
		}
		defer zr.Close()
		body = zr
	}
	var b event.Batch
	if err := json.NewDecoder(io.LimitReader(body, maxBatchJSON)).Decode(&b); err != nil {
		fail(w, http.StatusBadRequest, "invalid batch")
		return
	}
	if len(b.Requests)+len(b.Egress) > maxBatchItems {
		fail(w, http.StatusRequestEntityTooLarge, "batch too large")
		return
	}
	now := time.Now()
	b.Requests = sanitizeRequests(b.Requests, now)
	b.Egress = sanitizeEgress(b.Egress, now)
	b.Dropped = max(0, b.Dropped)
	if err := a.store.Ingest(r.Context(), sensorID, b, now); err != nil {
		internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// sanitizeRequests drops events with no valid IP and clamps everything else:
// sensors are trusted with a key, but the data inside came from the internet.
func sanitizeRequests(in []event.Request, now time.Time) []event.Request {
	out := in[:0]
	for _, r := range in {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		r.IP = ip.Unmap().String()
		if r.TS.Before(now.Add(-24*time.Hour)) || r.TS.After(now.Add(5*time.Minute)) {
			r.TS = now
		}
		r.Method, r.Host, r.Path, r.Query = clip(r.Method, 16), clip(r.Host, 255), clip(r.Path, 2048), clip(r.Query, 2048)
		r.Proto, r.UA, r.Referer = clip(r.Proto, 16), clip(r.UA, 512), clip(r.Referer, 512)
		r.JA4, r.SNI = clip(r.JA4, 64), clip(r.SNI, 255)
		r.Headers = r.Headers[:min(len(r.Headers), 64)]
		for i, h := range r.Headers {
			r.Headers[i] = clip(h, 64)
		}
		hints := make(map[string]string, len(r.Hints))
		for _, k := range append(event.HintHeaders, "webdriver") {
			if v, ok := r.Hints[k]; ok {
				hints[k] = clip(v, 1024)
			}
		}
		r.Hints = hints
		switch r.Action {
		case event.ActionAllow, event.ActionBlock, event.ActionChallenge, event.ActionChallengePassed, event.ActionRateLimit:
		default:
			r.Action = event.ActionAllow
		}
		out = append(out, r)
	}
	return out
}

func sanitizeEgress(in []event.Egress, now time.Time) []event.Egress {
	out := in[:0]
	for _, e := range in {
		ip, err := netip.ParseAddr(e.DstIP)
		if err != nil || e.Count <= 0 {
			continue
		}
		e.DstIP, e.Comm = ip.Unmap().String(), clip(e.Comm, 16)
		if e.TS.Before(now.Add(-24*time.Hour)) || e.TS.After(now.Add(5*time.Minute)) {
			e.TS = now
		}
		out = append(out, e)
	}
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (a *API) sensorDecisions(w http.ResponseWriter, r *http.Request, sensorID int64) {
	if err := a.store.TouchSensor(r.Context(), sensorID, time.Now()); err != nil {
		internal(w, r, err)
		return
	}
	ds, err := a.store.ActiveDecisions(r.Context(), time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	body, _ := json.Marshal(event.Decisions{Decisions: ds})
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// ---- dashboard session ------------------------------------------------------

func (a *API) sign(exp time.Time) string {
	buf := binary.BigEndian.AppendUint64(nil, uint64(exp.Unix()))
	m := hmac.New(sha256.New, a.sessionKey)
	m.Write(buf)
	return base64.RawURLEncoding.EncodeToString(append(buf, m.Sum(nil)...))
}

func (a *API) authenticated(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	m := hmac.New(sha256.New, a.sessionKey)
	m.Write(raw[:8])
	exp := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	return hmac.Equal(raw[8:], m.Sum(nil)) && time.Now().Before(exp)
}

// sameOrigin rejects cross-site writes. SameSite=Strict already keeps the
// cookie off them; this also covers older browsers.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	o, _ := strings.CutPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	return o == r.Host
}

func (a *API) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authenticated(r) {
			fail(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			fail(w, http.StatusForbidden, "forbidden")
			return
		}
		next(w, r)
	}
}

func (a *API) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": a.authenticated(r)})
}

func (a *API) setSession(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !a.logins.allow(clientIP(r)) {
		fail(w, http.StatusTooManyRequests, "too many attempts; wait a minute")
		return
	}
	if !sameOrigin(r) {
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !hmac.Equal([]byte(body.Token), []byte(a.adminToken)) {
		fail(w, http.StatusUnauthorized, "wrong token")
		return
	}
	a.setSession(w, r, a.sign(time.Now().Add(sessionTTL)), int(sessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.setSession(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
}

// ---- dashboard data ---------------------------------------------------------

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	o, err := a.store.Overview(r.Context(), time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": o, "llm": a.engine.LLM()})
}

func (a *API) actors(w http.ResponseWriter, r *http.Request) {
	filter := store.ActorFilter(r.URL.Query().Get("filter"))
	list, err := a.store.ListActors(r.Context(), filter, queryHours(r, 24), 300)
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) actor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	actor, err := a.store.Actor(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		internal(w, r, err)
		return
	}
	reqs, err := a.store.ActorRequests(r.Context(), id, time.Now().Add(-a.engine.cfg.Window), 300)
	if err != nil {
		internal(w, r, err)
		return
	}
	ds, err := a.store.ListDecisions(r.Context(), id, 50, time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actor": actor, "requests": reqs, "decisions": ds})
}

func (a *API) triageActor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	// Detach from the request so a closed tab doesn't waste a paid call.
	ctx := context.WithoutCancel(r.Context())
	v, err := a.engine.Triage(ctx, id)
	switch {
	case errors.Is(err, ErrTriageOff):
		fail(w, http.StatusConflict, "LLM triage is off: set OPENROUTER_API_KEY or ANTHROPIC_API_KEY on the server")
	case errors.Is(err, ErrTriageBusy):
		fail(w, http.StatusConflict, "triage already running")
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not found")
	case err != nil:
		slog.Error("manual triage failed", "actor", id, "err", err)
		fail(w, http.StatusBadGateway, "the model call failed; see server logs")
	default:
		writeJSON(w, http.StatusOK, v)
	}
}

func (a *API) dismissActor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Dismissed bool `json:"dismissed"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	err := a.store.SetDismissed(r.Context(), id, body.Dismissed, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"dismissed": body.Dismissed})
}

func (a *API) decisions(w http.ResponseWriter, r *http.Request) {
	ds, err := a.store.ListDecisions(r.Context(), 0, 300, time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, ds)
}

// createDecision is a manual decision. A human made it, so it is active at once.
func (a *API) createDecision(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ActorID    *int64             `json:"actor_id"`
		IP         string             `json:"ip"`
		JA4        string             `json:"ja4"`
		Kind       event.DecisionKind `json:"kind"`
		RPM        int                `json:"rpm"`
		TTLMinutes int                `json:"ttl_minutes"`
		Reason     string             `json:"reason"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	ip, err := netip.ParseAddr(body.IP)
	switch {
	case err != nil:
		fail(w, http.StatusBadRequest, "invalid ip")
		return
	case body.Kind != event.KindBlock && body.Kind != event.KindChallenge && body.Kind != event.KindRateLimit:
		fail(w, http.StatusBadRequest, "kind must be block, challenge or rate_limit")
		return
	case body.TTLMinutes < 1 || body.TTLMinutes > 60*24*90:
		fail(w, http.StatusBadRequest, "ttl_minutes must be between 1 and 129600")
		return
	case body.Kind == event.KindRateLimit && (body.RPM < 1 || body.RPM > 100_000):
		fail(w, http.StatusBadRequest, "rpm must be between 1 and 100000")
		return
	}
	reason := strings.TrimSpace(clip(body.Reason, 500))
	if reason == "" {
		reason = "Manual decision"
	}
	d, err := a.store.CreateDecision(r.Context(), store.Decision{
		ActorID: body.ActorID, IP: ip.Unmap().String(), JA4: clip(body.JA4, 64), Kind: body.Kind,
		RPM: body.RPM, TTLMinutes: body.TTLMinutes, Reason: reason, Source: "manual", Status: store.StatusActive,
	}, time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (a *API) transition(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var from, to store.DecisionStatus
	switch r.PathValue("verb") {
	case "approve":
		from, to = store.StatusPending, store.StatusActive
	case "reject":
		from, to = store.StatusPending, store.StatusRejected
	case "revoke":
		from, to = store.StatusActive, store.StatusRevoked
	default:
		fail(w, http.StatusNotFound, "not found")
		return
	}
	d, err := a.store.Transition(r.Context(), id, from, to, time.Now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		fail(w, http.StatusConflict, "decision is "+string(d.Status))
	case err != nil:
		internal(w, r, err)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (a *API) egress(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListEgress(r.Context(), queryHours(r, 24), 500)
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) sensors(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListSensors(r.Context())
	if err != nil {
		internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createSensor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(clip(body.Name, 80))
	if name == "" {
		fail(w, http.StatusBadRequest, "name is required")
		return
	}
	s, key, err := a.store.CreateSensor(r.Context(), name, time.Now())
	if err != nil {
		internal(w, r, err)
		return
	}
	// The key is shown once; only its hash is stored.
	writeJSON(w, http.StatusCreated, map[string]any{"sensor": s, "key": key})
}

func (a *API) deleteSensor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := a.store.DeleteSensor(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- UI -----------------------------------------------------------------------

// static serves the built dashboard; unknown paths get index.html so client
// routes survive a reload.
func (a *API) static() http.Handler {
	files := http.FileServerFS(a.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			fail(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := a.ui.Open(p); err == nil {
				f.Close()
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(a.ui, "index.html")
		if err != nil {
			http.Error(w, "dashboard not built: run `bun run build` in web/", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
	})
}
