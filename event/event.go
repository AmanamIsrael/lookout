// Package event defines the wire format between the sensor and the server.
package event

import "time"

// Batch is one upload from a sensor to POST /v1/ingest.
type Batch struct {
	Requests []Request `json:"requests,omitempty"`
	Egress   []Egress  `json:"egress,omitempty"`
	// Dropped counts events the sensor discarded because its buffer was full.
	Dropped int `json:"dropped,omitempty"`
}

// Request is one inbound HTTP request seen by the sensor proxy.
type Request struct {
	TS         time.Time `json:"ts"`
	IP         string    `json:"ip"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	Proto      string    `json:"proto"`
	Status     int       `json:"status"`
	DurationMS float64   `json:"duration_ms"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
	UA         string    `json:"ua,omitempty"`
	Referer    string    `json:"referer,omitempty"`
	// Headers lists the lower-case header names present, sorted.
	Headers []string `json:"headers,omitempty"`
	// Hints holds the values of the headers in HintHeaders that were present.
	Hints map[string]string `json:"hints,omitempty"`
	JA4   string            `json:"ja4,omitempty"`
	SNI   string            `json:"sni,omitempty"`
	// Action is what the sensor did with the request.
	Action     Action `json:"action"`
	DecisionID int64  `json:"decision_id,omitempty"`
}

// HintHeaders are the header values worth keeping for classification and
// Web Bot Auth verification. Everything else is recorded by name only.
var HintHeaders = []string{
	"accept",
	"accept-language",
	"accept-encoding",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"from",
	"signature-agent",
	"signature-input",
	"signature",
}

// Action is the sensor's response to a request.
type Action string

const (
	ActionAllow           Action = "allow"
	ActionBlock           Action = "block"
	ActionChallenge       Action = "challenge"
	ActionChallengePassed Action = "challenge_passed"
	ActionRateLimit       Action = "rate_limit"
)

// Egress is an aggregated outbound TCP flow seen by the eBPF probe:
// Count connections from one process to one destination within a window.
type Egress struct {
	TS      time.Time `json:"ts"`
	Comm    string    `json:"comm"`
	PID     uint32    `json:"pid"`
	UID     uint32    `json:"uid"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Count   int       `json:"count"`
}

// Decision is an enforcement rule the sensor pulls from GET /v1/decisions.
// It matches every request from IP, or only those that also carry JA4 when set.
type Decision struct {
	ID        int64        `json:"id"`
	Kind      DecisionKind `json:"kind"`
	IP        string       `json:"ip"`
	JA4       string       `json:"ja4,omitempty"`
	RPM       int          `json:"rpm,omitempty"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// DecisionKind is the enforcement a Decision applies.
type DecisionKind string

const (
	KindBlock     DecisionKind = "block"
	KindChallenge DecisionKind = "challenge"
	KindRateLimit DecisionKind = "rate_limit"
)

// Decisions is the body of GET /v1/decisions.
type Decisions struct {
	Decisions []Decision `json:"decisions"`
}
