// Package analyze scores an actor's requests with deterministic rules.
//
// Rules are cheap and run on every actor. Each fired rule becomes a Signal
// with a weight and a sentence a human (and the LLM triage) can read. The
// LLM only looks at actors the rules find interesting.
package analyze

import (
	"fmt"
	"math"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/AmanamIsrael/lookout/event"
)

// Signal is one rule that fired.
type Signal struct {
	Code   string `json:"code"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

// Classes, from most to least specific.
const (
	ClassImpersonator = "impersonator" // claims to be a bot it is not
	ClassScanner      = "scanner"      // probes for vulnerabilities
	ClassVerifiedBot  = "verified_bot" // identity proven (reverse DNS or Web Bot Auth)
	ClassAIAgent      = "ai_agent"     // declared or behaves like an LLM agent
	ClassAutomation   = "automation"   // scripts, headless browsers, HTTP libraries
	ClassCrawler      = "crawler"      // declared search crawler, or broad crawling
	ClassBrowser      = "browser"      // looks like a person in a browser
	ClassUnknown      = "unknown"
)

// Identity is the outcome of verifying a claimed identity.
type Identity struct {
	// Verified names the proven identity, e.g. "Googlebot (reverse DNS)".
	Verified string `json:"verified,omitempty"`
	// Failed explains a claim that did not check out.
	Failed string `json:"failed,omitempty"`
}

// Result is the rule verdict for one actor.
type Result struct {
	Score   int      `json:"score"`
	Class   string   `json:"class"`
	Signals []Signal `json:"signals"`
}

// Summary is a compact description of an actor's traffic.
type Summary struct {
	Requests      int            `json:"requests"`
	Span          string         `json:"span"`
	DistinctPaths int            `json:"distinct_paths"`
	PeakPerMinute int            `json:"peak_per_minute"`
	Methods       map[string]int `json:"methods"`
	Statuses      map[int]int    `json:"statuses"`
	Actions       map[string]int `json:"sensor_actions"`
	Documents     int            `json:"document_requests"`
	Assets        int            `json:"asset_requests"`
	MedianGap     string         `json:"median_gap,omitempty"`
	UserAgents    []string       `json:"user_agents"`
}

var assetExt = map[string]bool{
	".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".webp": true, ".avif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true,
	".map": true, ".webmanifest": true,
}

func isAsset(r event.Request) bool {
	switch r.Hints["sec-fetch-dest"] {
	case "script", "style", "image", "font", "manifest":
		return true
	}
	return assetExt[strings.ToLower(path.Ext(r.Path))]
}

func isDocument(r event.Request) bool {
	return r.Method == "GET" && !isAsset(r) &&
		(r.Hints["sec-fetch-dest"] == "document" || strings.Contains(r.Hints["accept"], "text/html") ||
			strings.Contains(r.Hints["accept"], "text/markdown"))
}

// Summarize describes reqs, which must be sorted oldest first.
func Summarize(reqs []event.Request) Summary {
	s := Summary{
		Requests: len(reqs),
		Methods:  map[string]int{},
		Statuses: map[int]int{},
		Actions:  map[string]int{},
	}
	if len(reqs) == 0 {
		return s
	}
	paths := map[string]bool{}
	uas := map[string]bool{}
	for _, r := range reqs {
		paths[r.Path] = true
		s.Methods[r.Method]++
		s.Statuses[r.Status]++
		s.Actions[string(r.Action)]++
		if isAsset(r) {
			s.Assets++
		} else if isDocument(r) {
			s.Documents++
		}
		if !uas[r.UA] && len(uas) < 5 {
			uas[r.UA] = true
			s.UserAgents = append(s.UserAgents, r.UA)
		}
	}
	s.DistinctPaths = len(paths)
	s.Span = reqs[len(reqs)-1].TS.Sub(reqs[0].TS).Round(time.Second).String()
	s.PeakPerMinute = peakPerMinute(reqs)
	if gaps := burstGaps(reqs); len(gaps) > 0 {
		s.MedianGap = median(gaps).Round(10 * time.Millisecond).String()
	}
	return s
}

// Analyze scores reqs (oldest first) for one actor.
func Analyze(reqs []event.Request, id Identity) Result {
	if len(reqs) == 0 {
		return Result{Class: ClassUnknown, Signals: []Signal{}}
	}
	var sig []Signal
	add := func(code string, w int, format string, args ...any) {
		sig = append(sig, Signal{Code: code, Weight: w, Detail: fmt.Sprintf(format, args...)})
	}
	sum := Summarize(reqs)
	ua := reqs[len(reqs)-1].UA
	family := browserFamily(ua)
	agent, declared := ClaimedAgent(ua)
	class := ""
	setClass := func(c string) {
		if class == "" || classRank[c] < classRank[class] {
			class = c
		}
	}

	// --- identity -------------------------------------------------------------
	switch {
	case id.Failed != "":
		// A claim proven false (forged crawler, forged signature) is deliberate deception.
		add("identity_failed", 80, "%s", id.Failed)
		setClass(ClassImpersonator)
	case id.Verified != "":
		add("verified", 0, "Identity verified: %s", id.Verified)
	case declared:
		w := 5
		if agent.IsAI() {
			w = 10
		}
		add("declared_agent", w, "Declares itself as %s (%s, %s); identity not verified", agent.Token, agent.Operator, agent.Kind)
	}
	if declared && id.Failed == "" {
		if agent.IsAI() {
			setClass(ClassAIAgent)
		} else {
			setClass(ClassCrawler)
		}
	}

	// --- attacks ----------------------------------------------------------------
	if hits := attackHits(reqs); len(hits) > 0 {
		add("attack_paths", 25+5*min(len(hits)-1, 7), "%d requests probe for vulnerabilities, e.g. %s", len(hits), strings.Join(hits[:min(3, len(hits))], ", "))
		setClass(ClassScanner)
	}
	if t := matchToken(ua, scannerTokens); t != "" {
		add("scanner_tool", 40, "User-Agent names the scanner %q", t)
		setClass(ClassScanner)
	}

	// --- client consistency -----------------------------------------------------
	if ua == "" {
		add("empty_ua", 20, "No User-Agent header")
		setClass(ClassAutomation)
	} else if t := matchToken(ua, automationTokens); t != "" && !slices.Contains(scannerTokens, t) {
		add("automation_ua", 20, "User-Agent names the HTTP tool %q", t)
		setClass(ClassAutomation)
	}
	if family != "" {
		ja4 := reqs[len(reqs)-1].JA4
		if v, alpn, ok := parseJA4(ja4); ok && (alpn != "h2" || v != "13") {
			add("ua_tls_mismatch", 30, "Claims to be %s but its TLS handshake (%s) is not a browser's: TLS %s, ALPN %q", family, ja4, v, alpn)
			setClass(ClassAutomation)
		}
		missingFetch, missingLang, missingCH := 0, 0, 0
		for _, r := range reqs {
			if r.Hints["sec-fetch-mode"] == "" {
				missingFetch++
			}
			if r.Hints["accept-language"] == "" {
				missingLang++
			}
			if r.Hints["sec-ch-ua"] == "" {
				missingCH++
			}
		}
		n := len(reqs)
		if missingFetch*2 > n {
			add("missing_fetch_metadata", 25, "Claims to be %s but %d of %d requests lack Sec-Fetch-* headers every modern browser sends", family, missingFetch, n)
			setClass(ClassAutomation)
		}
		if family == "chrome" && reqs[n-1].JA4 != "" && missingCH*2 > n {
			add("missing_client_hints", 10, "Claims Chrome over HTTPS but sends no Sec-CH-UA client hints")
		}
		if missingLang*2 > n {
			add("missing_accept_language", 10, "Claims to be %s but sends no Accept-Language", family)
		}
		if sum.Documents >= 8 && sum.Assets == 0 {
			add("no_assets", 15, "Fetched %d pages but no CSS, JS, images or fonts", sum.Documents)
		}
		if slices.ContainsFunc(reqs, func(r event.Request) bool { return r.Path == "/robots.txt" }) {
			add("browser_robots", 10, "Claims to be a browser but fetched /robots.txt")
		}
	}
	if slices.ContainsFunc(reqs, func(r event.Request) bool { return r.Hints["webdriver"] == "1" }) {
		add("webdriver", 30, "The browser challenge reported navigator.webdriver: an automated browser")
		setClass(ClassAutomation)
	}

	// --- LLM-agent tells --------------------------------------------------------
	markdown := 0
	for _, r := range reqs {
		if strings.Contains(r.Hints["accept"], "text/markdown") || strings.Contains(r.Hints["accept"], "text/x-markdown") {
			markdown++
		}
	}
	if markdown > 0 {
		add("accepts_markdown", 15, "%d requests ask for text/markdown, typical of LLM fetch tools", markdown)
		setClass(ClassAIAgent)
	}
	gaps := burstGaps(reqs)
	if len(gaps) >= 6 && sum.Assets == 0 && sum.Documents*2 >= len(reqs) {
		m, cv := median(gaps), coeffVar(gaps)
		if m >= 2*time.Second && m <= 30*time.Second && cv >= 0.3 {
			add("llm_pacing", 15, "Reads pages with irregular %s pauses and loads no assets, like an LLM agent thinking between steps", m.Round(100*time.Millisecond))
			setClass(ClassAIAgent)
		}
	}

	// --- behaviour --------------------------------------------------------------
	if len(gaps) >= 10 {
		// Parallel bursts have near-zero gaps; only steady pacing counts.
		if m, cv := mean(gaps), coeffVar(gaps); m >= 200*time.Millisecond && cv < 0.2 {
			add("machine_timing", 20, "Requests arrive like clockwork: every %s (variation %.0f%%)", m.Round(10*time.Millisecond), cv*100)
			setClass(ClassAutomation)
		}
	}
	switch p := sum.PeakPerMinute; {
	case p > 600:
		add("high_rate", 30, "Peaked at %d requests per minute", p)
	case p > 120:
		add("high_rate", 15, "Peaked at %d requests per minute", p)
	}
	if n := len(reqs); n >= 20 {
		errs := 0
		for _, r := range reqs {
			if r.Action == event.ActionAllow && (r.Status == 404 || r.Status == 403 || r.Status == 401 || r.Status == 405) {
				errs++
			}
		}
		if errs*10 > n*4 {
			add("error_ratio", 20, "%d of %d requests hit 401/403/404/405: probing for what exists", errs, n)
		}
	}
	if tmpl, count := enumeration(reqs); count >= 15 {
		add("id_enumeration", 20, "Walked %d different IDs under %s", count, tmpl)
	}
	if sum.DistinctPaths >= 100 {
		add("broad_crawl", 10, "Requested %d distinct paths", sum.DistinctPaths)
		setClass(ClassCrawler)
	}

	// --- reaction to enforcement ------------------------------------------------
	challenged, passed := sum.Actions[string(event.ActionChallenge)], sum.Actions[string(event.ActionChallengePassed)]
	if challenged >= 3 && passed == 0 {
		add("challenge_failed", 15, "Got the browser challenge %d times and never passed it", challenged)
	}
	if passed > 0 {
		add("challenge_passed", -10, "Passed the browser challenge")
	}
	if b := sum.Actions[string(event.ActionBlock)]; b >= 10 {
		add("persists_when_blocked", 10, "Kept going after %d blocked requests", b)
	}

	// --- verdict -----------------------------------------------------------------
	score := 0
	attack := false
	for _, s := range sig {
		score += s.Weight
		attack = attack || s.Code == "attack_paths" || s.Code == "scanner_tool"
	}
	score = max(0, min(100, score))
	if id.Verified != "" && !attack {
		score = min(score, 5)
		class = ClassVerifiedBot
	}
	if class == "" {
		class = ClassUnknown
		if family != "" && score < 20 {
			class = ClassBrowser
		}
	}
	sort.SliceStable(sig, func(i, j int) bool { return sig[i].Weight > sig[j].Weight })
	if sig == nil {
		sig = []Signal{}
	}
	return Result{Score: score, Class: class, Signals: sig}
}

var classRank = map[string]int{
	ClassImpersonator: 0, ClassScanner: 1, ClassVerifiedBot: 2, ClassAIAgent: 3,
	ClassAutomation: 4, ClassCrawler: 5, ClassBrowser: 6, ClassUnknown: 7,
}

var attackPattern = regexp.MustCompile(`(?i)(/\.env|/\.git/|/\.aws/|/\.ssh/|/\.htaccess|/\.ds_store|wp-login\.php|/wp-admin|xmlrpc\.php|phpmyadmin|/cgi-bin/|/etc/passwd|\.\./|\.\.\\|union[\s+]+(all[\s+]+)?select|<script|javascript:|/actuator|/server-status|/vendor/phpunit|\.(bak|sql|old|swp)$|/config\.(json|php|ya?ml)$|/boaform|/hnap1|\$\{jndi:|/solr/|/owa/|sleep\(\d+\)|'\s*or\s*'?1'?\s*=\s*'?1|/\.well-known/acme-challenge/\.\.)`)

func attackHits(reqs []event.Request) []string {
	var hits []string
	for _, r := range reqs {
		target := r.Path
		if r.Query != "" {
			target += "?" + r.Query
		}
		if dec, err := url.QueryUnescape(target); err == nil {
			target = dec
		}
		if attackPattern.MatchString(target) {
			hits = append(hits, clip(r.Path, 60))
		}
	}
	return hits
}

// parseJA4 reads the TLS version and ALPN from a JA4's first part,
// e.g. t13d1516h2 -> "13", "h2".
func parseJA4(ja4 string) (version, alpn string, ok bool) {
	a, _, _ := strings.Cut(ja4, "_")
	if len(a) != 10 {
		return "", "", false
	}
	return a[1:3], a[8:10], true
}

// enumeration finds the path template with the most distinct numeric IDs,
// e.g. /api/users/{id} requested for 37 different users.
func enumeration(reqs []event.Request) (string, int) {
	ids := map[string]map[string]bool{}
	for _, r := range reqs {
		segs := strings.Split(r.Path, "/")
		var nums []string
		for i, seg := range segs {
			if seg != "" && strings.Trim(seg, "0123456789") == "" {
				nums = append(nums, seg)
				segs[i] = "{id}"
			}
		}
		if len(nums) == 0 {
			continue
		}
		tmpl := strings.Join(segs, "/")
		if ids[tmpl] == nil {
			ids[tmpl] = map[string]bool{}
		}
		ids[tmpl][strings.Join(nums, "/")] = true
	}
	best, n := "", 0
	for t, set := range ids {
		if len(set) > n {
			best, n = t, len(set)
		}
	}
	return best, n
}

func peakPerMinute(reqs []event.Request) int {
	peak, lo := 0, 0
	for hi := range reqs {
		for reqs[hi].TS.Sub(reqs[lo].TS) >= time.Minute {
			lo++
		}
		peak = max(peak, hi-lo+1)
	}
	return peak
}

// burstGaps are the gaps between consecutive requests, ignoring pauses over
// five minutes (separate visits).
func burstGaps(reqs []event.Request) []time.Duration {
	var out []time.Duration
	for i := 1; i < len(reqs); i++ {
		if g := reqs[i].TS.Sub(reqs[i-1].TS); g <= 5*time.Minute {
			out = append(out, g)
		}
	}
	return out
}

func mean(ds []time.Duration) time.Duration {
	var t time.Duration
	for _, d := range ds {
		t += d
	}
	return t / time.Duration(len(ds))
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[len(s)/2]
}

func coeffVar(ds []time.Duration) float64 {
	m := float64(mean(ds))
	if m == 0 {
		return 0
	}
	var v float64
	for _, d := range ds {
		v += (float64(d) - m) * (float64(d) - m)
	}
	return math.Sqrt(v/float64(len(ds))) / m
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
