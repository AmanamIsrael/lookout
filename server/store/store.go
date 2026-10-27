// Package store keeps lookout's state in one SQLite file.
//
// Requests are grouped into actors: one client IP with one TLS fingerprint.
// An actor is the unit the analyzer scores, the LLM triages and the UI lists.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/AmanamIsrael/lookout/event"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflicting state")
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS sensors (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL,
	key_hash     TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER,
	egress_since INTEGER,
	dropped      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS actors (
	id               INTEGER PRIMARY KEY,
	key              TEXT NOT NULL UNIQUE,
	ip               TEXT NOT NULL,
	ja4              TEXT NOT NULL,
	ua               TEXT NOT NULL DEFAULT '',
	first_seen       INTEGER NOT NULL,
	last_seen        INTEGER NOT NULL,
	requests         INTEGER NOT NULL DEFAULT 0,
	analyzed_at      INTEGER NOT NULL DEFAULT 0,
	rule_score       INTEGER NOT NULL DEFAULT 0,
	class            TEXT NOT NULL DEFAULT 'unknown',
	signals          TEXT NOT NULL DEFAULT '[]',
	verified         TEXT NOT NULL DEFAULT '',
	triage           TEXT,
	triage_score     INTEGER,
	triaged_at       INTEGER,
	triaged_requests INTEGER NOT NULL DEFAULT 0,
	risk             INTEGER NOT NULL DEFAULT 0,
	dismissed_at     INTEGER
);
CREATE INDEX IF NOT EXISTS actors_risk ON actors(risk DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS actors_last_seen ON actors(last_seen);
CREATE TABLE IF NOT EXISTS requests (
	id          INTEGER PRIMARY KEY,
	sensor_id   INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
	actor_id    INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
	ts          INTEGER NOT NULL,
	ip          TEXT NOT NULL,
	method      TEXT NOT NULL,
	host        TEXT NOT NULL,
	path        TEXT NOT NULL,
	query       TEXT NOT NULL,
	proto       TEXT NOT NULL,
	status      INTEGER NOT NULL,
	duration_ms REAL NOT NULL,
	bytes_in    INTEGER NOT NULL,
	bytes_out   INTEGER NOT NULL,
	ua          TEXT NOT NULL,
	referer     TEXT NOT NULL,
	headers     TEXT NOT NULL,
	hints       TEXT NOT NULL,
	ja4         TEXT NOT NULL,
	sni         TEXT NOT NULL,
	action      TEXT NOT NULL,
	decision_id INTEGER
);
CREATE INDEX IF NOT EXISTS requests_actor_ts ON requests(actor_id, ts);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE TABLE IF NOT EXISTS decisions (
	id          INTEGER PRIMARY KEY,
	actor_id    INTEGER REFERENCES actors(id) ON DELETE SET NULL,
	ip          TEXT NOT NULL,
	ja4         TEXT NOT NULL DEFAULT '',
	kind        TEXT NOT NULL,
	rpm         INTEGER NOT NULL DEFAULT 0,
	ttl_minutes INTEGER NOT NULL,
	reason      TEXT NOT NULL,
	source      TEXT NOT NULL,
	status      TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	decided_at  INTEGER,
	expires_at  INTEGER
);
CREATE INDEX IF NOT EXISTS decisions_status ON decisions(status, expires_at);
CREATE TABLE IF NOT EXISTS egress (
	id          INTEGER PRIMARY KEY,
	sensor_id   INTEGER NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
	comm        TEXT NOT NULL,
	uid         INTEGER NOT NULL,
	dst_ip      TEXT NOT NULL,
	dst_port    INTEGER NOT NULL,
	first_seen  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL,
	connections INTEGER NOT NULL,
	last_pid    INTEGER NOT NULL,
	flags       TEXT NOT NULL DEFAULT '[]',
	UNIQUE (sensor_id, comm, uid, dst_ip, dst_port)
);
CREATE INDEX IF NOT EXISTS egress_last_seen ON egress(last_seen);
`

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

// ---- sensors ----------------------------------------------------------------

type Sensor struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
	EgressSince *time.Time `json:"egress_since"`
	Dropped     int64      `json:"dropped"`
}

// HashKey is how sensor keys are stored: only the SHA-256 is kept.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreateSensor returns the new sensor and its key. The key is not stored.
func (s *Store) CreateSensor(ctx context.Context, name string, now time.Time) (Sensor, string, error) {
	raw := make([]byte, 24)
	rand.Read(raw)
	key := "lk_" + hex.EncodeToString(raw)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO sensors (name, key_hash, created_at) VALUES (?, ?, ?)`, name, HashKey(key), ms(now))
	if err != nil {
		return Sensor{}, "", err
	}
	id, _ := res.LastInsertId()
	return Sensor{ID: id, Name: name, CreatedAt: now.UTC()}, key, nil
}

func (s *Store) SensorIDByKey(ctx context.Context, key string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM sensors WHERE key_hash = ?`, HashKey(key)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) ListSensors(ctx context.Context) ([]Sensor, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at, last_seen_at, egress_since, dropped FROM sensors ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Sensor{}
	for rows.Next() {
		var x Sensor
		var created int64
		var seen, egress sql.NullInt64
		if err := rows.Scan(&x.ID, &x.Name, &created, &seen, &egress, &x.Dropped); err != nil {
			return nil, err
		}
		x.CreatedAt = time.UnixMilli(created).UTC()
		x.LastSeenAt, x.EgressSince = fromMS(seen), fromMS(egress)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSensor(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sensors WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- ingest -----------------------------------------------------------------

// ActorKey groups requests: one IP with one TLS fingerprint.
func ActorKey(ip, ja4 string) string { return ip + "|" + ja4 }

// TouchSensor records that a sensor checked in. Sensors poll for decisions
// every few seconds, so this is their heartbeat even when traffic is quiet.
func (s *Store) TouchSensor(ctx context.Context, sensorID int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sensors SET last_seen_at = ? WHERE id = ?`, ms(now), sensorID)
	return err
}

// Ingest stores a batch in one transaction.
func (s *Store) Ingest(ctx context.Context, sensorID int64, b event.Batch, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE sensors SET last_seen_at = ?, dropped = dropped + ? WHERE id = ?`, ms(now), b.Dropped, sensorID); err != nil {
		return err
	}

	upsertActor, err := tx.PrepareContext(ctx, `
		INSERT INTO actors (key, ip, ja4, ua, first_seen, last_seen, requests)
		VALUES (?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(key) DO UPDATE SET
			last_seen = max(last_seen, excluded.last_seen),
			first_seen = min(first_seen, excluded.first_seen),
			ua = CASE WHEN excluded.ua != '' THEN excluded.ua ELSE ua END,
			requests = requests + 1
		RETURNING id`)
	if err != nil {
		return err
	}
	defer upsertActor.Close()
	insertReq, err := tx.PrepareContext(ctx, `
		INSERT INTO requests (sensor_id, actor_id, ts, ip, method, host, path, query, proto, status,
			duration_ms, bytes_in, bytes_out, ua, referer, headers, hints, ja4, sni, action, decision_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insertReq.Close()

	for _, r := range b.Requests {
		ts := ms(r.TS)
		var actorID int64
		if err := upsertActor.QueryRowContext(ctx,
			ActorKey(r.IP, r.JA4), r.IP, r.JA4, r.UA, ts, ts).Scan(&actorID); err != nil {
			return err
		}
		headers, _ := json.Marshal(r.Headers)
		hints, _ := json.Marshal(r.Hints)
		var decision sql.NullInt64
		if r.DecisionID != 0 {
			decision = sql.NullInt64{Int64: r.DecisionID, Valid: true}
		}
		if _, err := insertReq.ExecContext(ctx,
			sensorID, actorID, ts, r.IP, r.Method, r.Host, r.Path, r.Query, r.Proto, r.Status,
			r.DurationMS, r.BytesIn, r.BytesOut, r.UA, r.Referer, string(headers), string(hints),
			r.JA4, r.SNI, string(r.Action), decision); err != nil {
			return err
		}
	}

	if len(b.Egress) > 0 {
		if err := upsertEgress(ctx, tx, sensorID, b.Egress, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- actors -----------------------------------------------------------------

type Actor struct {
	ID              int64           `json:"id"`
	IP              string          `json:"ip"`
	JA4             string          `json:"ja4"`
	UA              string          `json:"ua"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	Requests        int64           `json:"requests"`
	RuleScore       int             `json:"rule_score"`
	Class           string          `json:"class"`
	Signals         json.RawMessage `json:"signals"`
	Verified        string          `json:"verified"`
	Triage          json.RawMessage `json:"triage"`
	TriageScore     *int            `json:"triage_score"`
	TriagedAt       *time.Time      `json:"triaged_at"`
	TriagedRequests int64           `json:"-"`
	Risk            int             `json:"risk"`
	DismissedAt     *time.Time      `json:"dismissed_at"`
	AnalyzedAt      time.Time       `json:"-"`
}

const actorCols = `id, ip, ja4, ua, first_seen, last_seen, requests, rule_score, class, signals,
	verified, triage, triage_score, triaged_at, triaged_requests, risk, dismissed_at, analyzed_at`

func scanActor(sc interface{ Scan(...any) error }) (Actor, error) {
	var a Actor
	var first, last, analyzed int64
	var signals string
	var triage sql.NullString
	var triageScore sql.NullInt64
	var triagedAt, dismissed sql.NullInt64
	err := sc.Scan(&a.ID, &a.IP, &a.JA4, &a.UA, &first, &last, &a.Requests, &a.RuleScore, &a.Class,
		&signals, &a.Verified, &triage, &triageScore, &triagedAt, &a.TriagedRequests, &a.Risk, &dismissed, &analyzed)
	if err != nil {
		return a, err
	}
	a.FirstSeen, a.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
	a.AnalyzedAt = time.UnixMilli(analyzed).UTC()
	a.Signals = json.RawMessage(signals)
	if triage.Valid {
		a.Triage = json.RawMessage(triage.String)
	}
	if triageScore.Valid {
		v := int(triageScore.Int64)
		a.TriageScore = &v
	}
	a.TriagedAt, a.DismissedAt = fromMS(triagedAt), fromMS(dismissed)
	return a, nil
}

func (s *Store) queryActors(ctx context.Context, q string, args ...any) ([]Actor, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Actor{}
	for rows.Next() {
		a, err := scanActor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) Actor(ctx context.Context, id int64) (Actor, error) {
	a, err := scanActor(s.db.QueryRowContext(ctx, `SELECT `+actorCols+` FROM actors WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// ActorFilter narrows ListActors.
type ActorFilter string

const (
	FilterAll        ActorFilter = "all"
	FilterSuspicious ActorFilter = "suspicious" // risk >= 50, not dismissed
	FilterAgents     ActorFilter = "agents"     // declared or detected AI agents
	FilterVerified   ActorFilter = "verified"
	FilterDismissed  ActorFilter = "dismissed"
)

// ListActors returns actors seen since `since`, riskiest first.
func (s *Store) ListActors(ctx context.Context, f ActorFilter, since time.Time, limit int) ([]Actor, error) {
	where := `last_seen >= ?`
	switch f {
	case FilterSuspicious:
		where += ` AND risk >= 50 AND dismissed_at IS NULL`
	case FilterAgents:
		where += ` AND class = 'ai_agent'`
	case FilterVerified:
		where += ` AND verified != ''`
	case FilterDismissed:
		where += ` AND dismissed_at IS NOT NULL`
	default:
		where += ` AND dismissed_at IS NULL`
	}
	return s.queryActors(ctx, `SELECT `+actorCols+` FROM actors WHERE `+where+
		` ORDER BY risk DESC, last_seen DESC LIMIT ?`, ms(since), limit)
}

// ActorsToAnalyze returns actors with requests newer than their last analysis.
func (s *Store) ActorsToAnalyze(ctx context.Context, limit int) ([]Actor, error) {
	return s.queryActors(ctx, `SELECT `+actorCols+` FROM actors
		WHERE last_seen > analyzed_at ORDER BY last_seen DESC LIMIT ?`, limit)
}

// SaveAnalysis stores the rule verdict. Risk follows the LLM score when one
// exists, the rule score otherwise.
func (s *Store) SaveAnalysis(ctx context.Context, id int64, score int, class string, signals any, verified string, at time.Time) error {
	sig, err := json.Marshal(signals)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE actors SET rule_score = ?, class = ?, signals = ?, verified = ?,
		analyzed_at = ?, risk = coalesce(triage_score, ?) WHERE id = ?`,
		score, class, string(sig), verified, ms(at), score, id)
	return err
}

// ActorsToTriage returns actors worth an LLM look: rule score at or above
// minScore, not dismissed, and never triaged or grown by half since.
func (s *Store) ActorsToTriage(ctx context.Context, minScore, limit int) ([]Actor, error) {
	return s.queryActors(ctx, `SELECT `+actorCols+` FROM actors
		WHERE rule_score >= ? AND dismissed_at IS NULL
		  AND (triaged_at IS NULL OR requests >= triaged_requests * 1.5 + 10)
		ORDER BY rule_score DESC, last_seen DESC LIMIT ?`, minScore, limit)
}

func (s *Store) SaveTriage(ctx context.Context, id int64, verdict any, score int, requests int64, at time.Time) error {
	v, err := json.Marshal(verdict)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE actors SET triage = ?, triage_score = ?, triaged_at = ?,
		triaged_requests = ?, risk = ? WHERE id = ?`, string(v), score, ms(at), requests, score, id)
	return err
}

func (s *Store) SetDismissed(ctx context.Context, id int64, dismissed bool, now time.Time) error {
	var at any
	if dismissed {
		at = ms(now)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE actors SET dismissed_at = ? WHERE id = ?`, at, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ActorRequests returns up to limit of the actor's most recent requests
// since `since`, oldest first.
func (s *Store) ActorRequests(ctx context.Context, actorID int64, since time.Time, limit int) ([]event.Request, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM (
		SELECT ts, ip, method, host, path, query, proto, status, duration_ms, bytes_in, bytes_out,
			ua, referer, headers, hints, ja4, sni, action, coalesce(decision_id, 0)
		FROM requests WHERE actor_id = ? AND ts >= ? ORDER BY ts DESC LIMIT ?) ORDER BY ts`,
		actorID, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []event.Request{}
	for rows.Next() {
		var r event.Request
		var ts int64
		var headers, hints, action string
		if err := rows.Scan(&ts, &r.IP, &r.Method, &r.Host, &r.Path, &r.Query, &r.Proto, &r.Status,
			&r.DurationMS, &r.BytesIn, &r.BytesOut, &r.UA, &r.Referer, &headers, &hints, &r.JA4, &r.SNI,
			&action, &r.DecisionID); err != nil {
			return nil, err
		}
		r.TS = time.UnixMilli(ts).UTC()
		r.Action = event.Action(action)
		json.Unmarshal([]byte(headers), &r.Headers)
		json.Unmarshal([]byte(hints), &r.Hints)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- decisions --------------------------------------------------------------

type Decision struct {
	ID         int64              `json:"id"`
	ActorID    *int64             `json:"actor_id"`
	IP         string             `json:"ip"`
	JA4        string             `json:"ja4"`
	Kind       event.DecisionKind `json:"kind"`
	RPM        int                `json:"rpm"`
	TTLMinutes int                `json:"ttl_minutes"`
	Reason     string             `json:"reason"`
	Source     string             `json:"source"` // rules | llm | manual
	Status     DecisionStatus     `json:"status"`
	CreatedAt  time.Time          `json:"created_at"`
	DecidedAt  *time.Time         `json:"decided_at"`
	ExpiresAt  *time.Time         `json:"expires_at"`
	Actor      *DecisionActor     `json:"actor,omitempty"` // set by ListDecisions
}

// DecisionActor is what a decision list shows about the actor it targets.
type DecisionActor struct {
	UA    string `json:"ua"`
	Class string `json:"class"`
	Risk  int    `json:"risk"`
}

type DecisionStatus string

const (
	StatusPending  DecisionStatus = "pending"
	StatusActive   DecisionStatus = "active"
	StatusRejected DecisionStatus = "rejected"
	StatusRevoked  DecisionStatus = "revoked"
	StatusExpired  DecisionStatus = "expired" // derived: active past expires_at
)

// CreateDecision inserts d. Manual decisions start active; suggestions start
// pending until a human approves them.
func (s *Store) CreateDecision(ctx context.Context, d Decision, now time.Time) (Decision, error) {
	d.CreatedAt = now.UTC()
	var decided, expires any
	if d.Status == StatusActive {
		exp := now.Add(time.Duration(d.TTLMinutes) * time.Minute).UTC()
		d.DecidedAt, d.ExpiresAt = &d.CreatedAt, &exp
		decided, expires = ms(now), ms(exp)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO decisions
		(actor_id, ip, ja4, kind, rpm, ttl_minutes, reason, source, status, created_at, decided_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.ActorID, d.IP, d.JA4, d.Kind, d.RPM, d.TTLMinutes, d.Reason, d.Source, d.Status, ms(now), decided, expires)
	if err != nil {
		return d, err
	}
	d.ID, _ = res.LastInsertId()
	return d, nil
}

// HasOpenDecision reports whether the actor already has a pending or live
// decision, or had one rejected or revoked in the last day. Either way no
// new suggestion is needed.
func (s *Store) HasOpenDecision(ctx context.Context, actorID int64, now time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM decisions WHERE actor_id = ?1 AND (
		status = 'pending' OR (status = 'active' AND expires_at > ?2)
		OR (status IN ('rejected', 'revoked') AND decided_at > ?2 - 86400000))`, actorID, ms(now)).Scan(&n)
	return n > 0, err
}

// Transition moves a decision from one state to another. Approving starts
// its TTL. It fails with ErrConflict when the decision is not in `from`.
func (s *Store) Transition(ctx context.Context, id int64, from, to DecisionStatus, now time.Time) (Decision, error) {
	q := `UPDATE decisions SET status = ?1, decided_at = ?2 WHERE id = ?3 AND status = ?4`
	if to == StatusActive {
		q = `UPDATE decisions SET status = ?1, decided_at = ?2, expires_at = ?2 + ttl_minutes * 60000
			WHERE id = ?3 AND status = ?4`
	}
	res, err := s.db.ExecContext(ctx, q, to, ms(now), id, from)
	if err != nil {
		return Decision{}, err
	}
	d, err := s.decision(ctx, id)
	if err != nil {
		return d, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return d, ErrConflict
	}
	return d, nil
}

const decisionCols = `id, actor_id, ip, ja4, kind, rpm, ttl_minutes, reason, source, status, created_at, decided_at, expires_at`

func scanDecision(sc interface{ Scan(...any) error }, now time.Time) (Decision, error) {
	var d Decision
	var actor, decided, expires sql.NullInt64
	var created int64
	err := sc.Scan(&d.ID, &actor, &d.IP, &d.JA4, &d.Kind, &d.RPM, &d.TTLMinutes, &d.Reason, &d.Source,
		&d.Status, &created, &decided, &expires)
	if err != nil {
		return d, err
	}
	if actor.Valid {
		d.ActorID = &actor.Int64
	}
	d.CreatedAt = time.UnixMilli(created).UTC()
	d.DecidedAt, d.ExpiresAt = fromMS(decided), fromMS(expires)
	if d.Status == StatusActive && d.ExpiresAt != nil && !d.ExpiresAt.After(now) {
		d.Status = StatusExpired
	}
	return d, nil
}

func (s *Store) decision(ctx context.Context, id int64) (Decision, error) {
	d, err := scanDecision(s.db.QueryRowContext(ctx, `SELECT `+decisionCols+` FROM decisions WHERE id = ?`, id), time.Now())
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// ListDecisions returns decisions, newest first. actorID 0 means all actors.
func (s *Store) ListDecisions(ctx context.Context, actorID int64, limit int, now time.Time) ([]Decision, error) {
	q := `SELECT d.` + strings.ReplaceAll(decisionCols, ", ", ", d.") + `, a.ua, a.class, a.risk
		FROM decisions d LEFT JOIN actors a ON a.id = d.actor_id`
	args := []any{}
	if actorID != 0 {
		q += ` WHERE d.actor_id = ?`
		args = append(args, actorID)
	}
	q += ` ORDER BY CASE d.status WHEN 'pending' THEN 0 WHEN 'active' THEN 1 ELSE 2 END, d.id DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Decision{}
	for rows.Next() {
		var ua, class sql.NullString
		var risk sql.NullInt64
		d, err := scanDecision(scanWith{rows, []any{&ua, &class, &risk}}, now)
		if err != nil {
			return nil, err
		}
		if class.Valid {
			d.Actor = &DecisionActor{UA: ua.String, Class: class.String, Risk: int(risk.Int64)}
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// scanWith scans extra trailing columns after the ones its caller asks for.
type scanWith struct {
	sc    interface{ Scan(...any) error }
	extra []any
}

func (s scanWith) Scan(dest ...any) error { return s.sc.Scan(append(dest, s.extra...)...) }

// ActiveDecisions is what sensors enforce.
func (s *Store) ActiveDecisions(ctx context.Context, now time.Time) ([]event.Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, ip, ja4, rpm, expires_at FROM decisions
		WHERE status = 'active' AND expires_at > ? ORDER BY id`, ms(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []event.Decision{}
	for rows.Next() {
		var d event.Decision
		var exp int64
		if err := rows.Scan(&d.ID, &d.Kind, &d.IP, &d.JA4, &d.RPM, &exp); err != nil {
			return nil, err
		}
		d.ExpiresAt = time.UnixMilli(exp).UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- egress -----------------------------------------------------------------

type EgressDest struct {
	ID          int64     `json:"id"`
	SensorID    int64     `json:"sensor_id"`
	Comm        string    `json:"comm"`
	UID         uint32    `json:"uid"`
	DstIP       string    `json:"dst_ip"`
	DstPort     uint16    `json:"dst_port"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Connections int64     `json:"connections"`
	LastPID     uint32    `json:"last_pid"`
	Flags       []string  `json:"flags"`
}

// Ports that outbound app traffic normally uses. Anything else is flagged.
var commonPorts = map[uint16]bool{53: true, 80: true, 123: true, 443: true, 853: true}

// egressBaseline is how long a sensor reports egress before new
// destinations count as unusual.
const egressBaseline = time.Hour

func upsertEgress(ctx context.Context, tx *sql.Tx, sensorID int64, flows []event.Egress, now time.Time) error {
	var since sql.NullInt64
	if err := tx.QueryRowContext(ctx, `UPDATE sensors SET egress_since = coalesce(egress_since, ?)
		WHERE id = ? RETURNING egress_since`, ms(now), sensorID).Scan(&since); err != nil {
		return err
	}
	learning := now.Sub(time.UnixMilli(since.Int64)) < egressBaseline

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO egress
		(sensor_id, comm, uid, dst_ip, dst_port, first_seen, last_seen, connections, last_pid, flags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(sensor_id, comm, uid, dst_ip, dst_port) DO UPDATE SET
			last_seen = max(last_seen, excluded.last_seen),
			connections = connections + excluded.connections,
			last_pid = excluded.last_pid`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range flows {
		flags := []string{}
		if !learning {
			flags = append(flags, "new_destination")
		}
		if !commonPorts[f.DstPort] {
			flags = append(flags, "uncommon_port")
		}
		fj, _ := json.Marshal(flags)
		ts := ms(f.TS)
		if _, err := stmt.ExecContext(ctx, sensorID, f.Comm, f.UID, f.DstIP, f.DstPort, ts, ts,
			f.Count, f.PID, string(fj)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListEgress(ctx context.Context, since time.Time, limit int) ([]EgressDest, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, sensor_id, comm, uid, dst_ip, dst_port, first_seen,
		last_seen, connections, last_pid, flags FROM egress WHERE last_seen >= ?
		ORDER BY json_array_length(flags) DESC, first_seen DESC LIMIT ?`, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EgressDest{}
	for rows.Next() {
		var e EgressDest
		var first, last int64
		var flags string
		if err := rows.Scan(&e.ID, &e.SensorID, &e.Comm, &e.UID, &e.DstIP, &e.DstPort, &first, &last,
			&e.Connections, &e.LastPID, &flags); err != nil {
			return nil, err
		}
		e.FirstSeen, e.LastSeen = time.UnixMilli(first).UTC(), time.UnixMilli(last).UTC()
		json.Unmarshal([]byte(flags), &e.Flags)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- overview & retention ---------------------------------------------------

type Overview struct {
	Requests24h      int64     `json:"requests_24h"`
	Actors24h        int64     `json:"actors_24h"`
	Bands            RiskBands `json:"bands"`
	Agents24h        int64     `json:"agents_24h"`
	PendingDecisions int64     `json:"pending_decisions"`
	ActiveDecisions  int64     `json:"active_decisions"`
	FlaggedEgress    int64     `json:"flagged_egress"`
}

// RiskBands counts the actors seen in the last day that are not dismissed,
// by risk: hostile 80+, suspicious 50-79, watch 20-49, benign under 20.
type RiskBands struct {
	Hostile    int64 `json:"hostile"`
	Suspicious int64 `json:"suspicious"`
	Watch      int64 `json:"watch"`
	Benign     int64 `json:"benign"`
}

func (s *Store) Overview(ctx context.Context, now time.Time) (Overview, error) {
	var o Overview
	day := ms(now.Add(-24 * time.Hour))
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM requests WHERE ts >= ?1),
		(SELECT count(*) FROM actors WHERE last_seen >= ?1),
		(SELECT count(*) FROM actors WHERE last_seen >= ?1 AND class = 'ai_agent'),
		(SELECT count(*) FROM decisions WHERE status = 'pending'),
		(SELECT count(*) FROM decisions WHERE status = 'active' AND expires_at > ?2),
		(SELECT count(*) FROM egress WHERE last_seen >= ?1 AND flags != '[]'),
		coalesce(sum(risk >= 80), 0), coalesce(sum(risk >= 50 AND risk < 80), 0),
		coalesce(sum(risk >= 20 AND risk < 50), 0), coalesce(sum(risk < 20), 0)
		FROM actors WHERE last_seen >= ?1 AND dismissed_at IS NULL`, day, ms(now)).Scan(
		&o.Requests24h, &o.Actors24h, &o.Agents24h, &o.PendingDecisions, &o.ActiveDecisions,
		&o.FlaggedEgress, &o.Bands.Hostile, &o.Bands.Suspicious, &o.Bands.Watch, &o.Bands.Benign)
	return o, err
}

// Prune deletes requests and idle actors/egress older than the cutoff.
func (s *Store) Prune(ctx context.Context, before time.Time) error {
	cut := ms(before)
	for _, q := range []string{
		`DELETE FROM requests WHERE ts < ?`,
		`DELETE FROM actors WHERE last_seen < ? AND id NOT IN (SELECT actor_id FROM decisions
			WHERE actor_id IS NOT NULL AND status IN ('pending', 'active'))`,
		`DELETE FROM egress WHERE last_seen < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, cut); err != nil {
			return err
		}
	}
	return nil
}
