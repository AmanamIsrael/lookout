package analyze_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server/analyze"
)

const (
	chromeUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	chromeJA4 = "t13d1516h2_8daaf6152771_02713d6af862"
	pythonJA4 = "t13d4907h1_0d8feac7bc37_7395dae3b2f3" // http/1.1 only, as HTTP libraries send
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func browserHints(dest string) map[string]string {
	return map[string]string{
		"accept":          "text/html,application/xhtml+xml",
		"accept-language": "en-US,en;q=0.9",
		"sec-ch-ua":       `"Chromium";v="141"`,
		"sec-fetch-mode":  "navigate",
		"sec-fetch-site":  "none",
		"sec-fetch-dest":  dest,
	}
}

func req(at time.Duration, path, ua, ja4 string, status int, hints map[string]string) event.Request {
	return event.Request{
		TS: t0.Add(at), IP: "203.0.113.7", Method: "GET", Host: "example.com", Path: path,
		Status: status, UA: ua, JA4: ja4, Hints: hints, Action: event.ActionAllow,
	}
}

func codes(r analyze.Result) []string {
	var out []string
	for _, s := range r.Signals {
		out = append(out, s.Code)
	}
	return out
}

func TestRealBrowserStaysQuiet(t *testing.T) {
	var reqs []event.Request
	for page := range 5 {
		at := time.Duration(page) * 40 * time.Second
		reqs = append(reqs, req(at, fmt.Sprintf("/docs/%d", page), chromeUA, chromeJA4, 200, browserHints("document")))
		for i, asset := range []string{"/app.js", "/app.css", "/logo.svg"} {
			reqs = append(reqs, req(at+time.Duration(50*(i+1))*time.Millisecond, asset, chromeUA, chromeJA4, 200, browserHints("script")))
		}
	}
	r := analyze.Analyze(reqs, analyze.Identity{})
	if r.Score != 0 || r.Class != analyze.ClassBrowser {
		t.Fatalf("score %d class %s signals %v", r.Score, r.Class, codes(r))
	}
}

func TestScriptPretendingToBeChrome(t *testing.T) {
	var reqs []event.Request
	for i := range 12 {
		// No Sec-Fetch headers, no Accept-Language, HTTP library TLS.
		reqs = append(reqs, req(time.Duration(i)*7*time.Second, fmt.Sprintf("/pricing/%d", i), chromeUA, pythonJA4, 200,
			map[string]string{"accept": "text/html"}))
	}
	r := analyze.Analyze(reqs, analyze.Identity{})
	for _, want := range []string{"ua_tls_mismatch", "missing_fetch_metadata", "no_assets"} {
		if !slices.Contains(codes(r), want) {
			t.Errorf("missing signal %s in %v", want, codes(r))
		}
	}
	if r.Score < 50 || r.Class != analyze.ClassAutomation {
		t.Fatalf("score %d class %s", r.Score, r.Class)
	}
}

func TestScannerIsHostile(t *testing.T) {
	var reqs []event.Request
	for i, p := range []string{"/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/index.php?id=1%27%20or%20%271%27=%271", "/vendor/phpunit/x"} {
		reqs = append(reqs, req(time.Duration(i)*time.Second, p, "", "", 404, nil))
	}
	r := analyze.Analyze(reqs, analyze.Identity{})
	if r.Class != analyze.ClassScanner || r.Score < 60 {
		t.Fatalf("score %d class %s signals %v", r.Score, r.Class, codes(r))
	}
}

func TestImpersonatedCrawler(t *testing.T) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	reqs := []event.Request{req(0, "/", ua, "", 200, nil)}
	r := analyze.Analyze(reqs, analyze.Identity{Failed: "Claims to be Googlebot but resolves elsewhere"})
	if r.Class != analyze.ClassImpersonator || r.Score < 80 {
		t.Fatalf("score %d class %s", r.Score, r.Class)
	}
}

func TestVerifiedAIAgentIsCappedUnlessAttacking(t *testing.T) {
	ua := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)"
	id := analyze.Identity{Verified: "chatgpt.com (Web Bot Auth signature)"}
	var reqs []event.Request
	for i := range 30 {
		reqs = append(reqs, req(time.Duration(i)*time.Second, fmt.Sprintf("/a/%d", i), ua, chromeJA4, 200, nil))
	}
	r := analyze.Analyze(reqs, id)
	if r.Class != analyze.ClassVerifiedBot || r.Score > 5 {
		t.Fatalf("score %d class %s", r.Score, r.Class)
	}

	reqs = append(reqs, req(31*time.Second, "/.env", ua, chromeJA4, 404, nil))
	r = analyze.Analyze(reqs, id)
	if r.Class != analyze.ClassScanner || r.Score < 25 {
		t.Fatalf("verified agent probing /.env: score %d class %s", r.Score, r.Class)
	}
}

func TestUndeclaredLLMAgent(t *testing.T) {
	// Reads docs pages, asks for markdown, pauses irregularly between steps.
	gaps := []time.Duration{3, 9, 4, 14, 6, 21, 5, 11}
	at := time.Duration(0)
	reqs := []event.Request{}
	for i, g := range gaps {
		at += g * time.Second
		reqs = append(reqs, req(at, fmt.Sprintf("/docs/page-%d", i), "Mozilla/5.0 (compatible)", pythonJA4, 200,
			map[string]string{"accept": "text/markdown, text/html;q=0.9"}))
	}
	r := analyze.Analyze(reqs, analyze.Identity{})
	if r.Class != analyze.ClassAIAgent {
		t.Fatalf("class %s signals %v", r.Class, codes(r))
	}
	for _, want := range []string{"accepts_markdown", "llm_pacing"} {
		if !slices.Contains(codes(r), want) {
			t.Errorf("missing %s in %v", want, codes(r))
		}
	}
}

func TestEnumerationAndClockwork(t *testing.T) {
	var reqs []event.Request
	for i := range 40 {
		reqs = append(reqs, req(time.Duration(i)*500*time.Millisecond, fmt.Sprintf("/api/users/%d/orders", 1000+i), "python-requests/2.32", pythonJA4, 200, nil))
	}
	r := analyze.Analyze(reqs, analyze.Identity{})
	for _, want := range []string{"id_enumeration", "machine_timing", "automation_ua"} {
		if !slices.Contains(codes(r), want) {
			t.Errorf("missing %s in %v", want, codes(r))
		}
	}
	for _, s := range r.Signals {
		if s.Code == "id_enumeration" && s.Detail != "Walked 40 different IDs under /api/users/{id}/orders" {
			t.Errorf("detail: %q", s.Detail)
		}
	}
}

func TestParallelBurstIsNotClockwork(t *testing.T) {
	var reqs []event.Request
	for i := range 20 {
		reqs = append(reqs, req(0, fmt.Sprintf("/static/%d.png", i), chromeUA, chromeJA4, 200, browserHints("image")))
	}
	if slices.Contains(codes(analyze.Analyze(reqs, analyze.Identity{})), "machine_timing") {
		t.Fatal("same-millisecond asset burst flagged as machine timing")
	}
}
