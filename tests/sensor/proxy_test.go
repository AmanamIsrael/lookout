package sensor_test

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/sensor"
)

type rig struct {
	enforcer *sensor.Enforcer
	srv      *httptest.Server
	mu       sync.Mutex
	events   []event.Request
}

func newRig(t *testing.T, trusted ...netip.Prefix) *rig {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "app saw %s from %s", r.URL.Path, r.Header.Get("X-Forwarded-For"))
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	rg := &rig{enforcer: sensor.NewEnforcer()}
	proxy := sensor.NewProxy(sensor.ProxyConfig{
		Upstream: u, Enforcer: rg.enforcer, TrustedProxies: trusted,
		Emit: func(e event.Request) {
			rg.mu.Lock()
			rg.events = append(rg.events, e)
			rg.mu.Unlock()
		},
	})
	rg.srv = httptest.NewServer(proxy)
	t.Cleanup(rg.srv.Close)
	return rg
}

func (rg *rig) last() event.Request {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	return rg.events[len(rg.events)-1]
}

func decision(kind event.DecisionKind, rpm int) event.Decision {
	return event.Decision{ID: 1, Kind: kind, IP: "127.0.0.1", RPM: rpm, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestForwardsAndRecords(t *testing.T) {
	rg := newRig(t)
	resp, err := http.Get(rg.srv.URL + "/hello?q=1&api_key=secret")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(body), "app saw /hello") {
		t.Fatalf("body %q", body)
	}
	ev := rg.last()
	if ev.Status != 200 || ev.Action != event.ActionAllow || ev.IP != "127.0.0.1" || ev.BytesOut != int64(len(body)) {
		t.Fatalf("event %+v", ev)
	}
	if ev.Query != "q=1&api_key=[redacted]" {
		t.Fatalf("query %q", ev.Query)
	}
}

func TestBlockDecision(t *testing.T) {
	rg := newRig(t)
	rg.enforcer.Replace([]event.Decision{decision(event.KindBlock, 0)})
	resp, _ := http.Get(rg.srv.URL + "/")
	resp.Body.Close()
	if resp.StatusCode != 403 || rg.last().Action != event.ActionBlock || rg.last().DecisionID != 1 {
		t.Fatalf("status %d event %+v", resp.StatusCode, rg.last())
	}
}

func TestFingerprintScopedDecisionSkipsOtherClients(t *testing.T) {
	rg := newRig(t)
	d := decision(event.KindBlock, 0)
	d.JA4 = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb" // plain-HTTP test clients have no JA4
	rg.enforcer.Replace([]event.Decision{d})
	resp, _ := http.Get(rg.srv.URL + "/")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	rg := newRig(t)
	rg.enforcer.Replace([]event.Decision{decision(event.KindRateLimit, 2)})
	var codes []int
	for range 3 {
		resp, _ := http.Get(rg.srv.URL + "/")
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if fmt.Sprint(codes) != "[200 200 429]" {
		t.Fatalf("codes %v", codes)
	}
}

var challengeRe = regexp.MustCompile(`name="c" value="([^"]+)"`)

func solve(challenge string) string {
	for n := 0; ; n++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", challenge, n)))
		z := 0
		for _, b := range sum {
			if b != 0 {
				z += bits.LeadingZeros8(b)
				break
			}
			z += 8
		}
		if z >= 16 {
			return fmt.Sprint(n)
		}
	}
}

func TestChallengeFlow(t *testing.T) {
	rg := newRig(t)
	rg.enforcer.Replace([]event.Decision{decision(event.KindChallenge, 0)})
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	resp, _ := client.Get(rg.srv.URL + "/account?tab=1")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || rg.last().Action != event.ActionChallenge {
		t.Fatalf("status %d", resp.StatusCode)
	}
	m := challengeRe.FindSubmatch(page)
	if m == nil {
		t.Fatal("no challenge in page")
	}
	ch := string(m[1])

	// An automated browser that reports navigator.webdriver never passes.
	resp, _ = client.PostForm(rg.srv.URL+sensor.ChallengePath, url.Values{"c": {ch}, "n": {solve(ch)}, "w": {"1"}, "r": {"/account?tab=1"}})
	resp.Body.Close()
	if resp.StatusCode != 403 || rg.last().Hints["webdriver"] != "1" {
		t.Fatalf("webdriver: status %d hints %v", resp.StatusCode, rg.last().Hints)
	}

	// A wrong answer fails.
	resp, _ = client.PostForm(rg.srv.URL+sensor.ChallengePath, url.Values{"c": {ch}, "n": {"nope"}, "r": {"/"}})
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("wrong answer: status %d", resp.StatusCode)
	}

	// The right answer sets a pass and returns to the page.
	resp, _ = client.PostForm(rg.srv.URL+sensor.ChallengePath, url.Values{"c": {ch}, "n": {solve(ch)}, "w": {"0"}, "r": {"/account?tab=1"}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(string(body), "app saw /account") {
		t.Fatalf("after pass: status %d body %q", resp.StatusCode, body)
	}
	if rg.last().Action != event.ActionAllow {
		t.Fatalf("last action %s", rg.last().Action)
	}
}

func TestChallengeRedirectStaysOnSite(t *testing.T) {
	rg := newRig(t)
	rg.enforcer.Replace([]event.Decision{decision(event.KindChallenge, 0)})
	resp, _ := http.Get(rg.srv.URL + "/")
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ch := string(challengeRe.FindSubmatch(page)[1])
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ = noFollow.PostForm(rg.srv.URL+sensor.ChallengePath, url.Values{"c": {ch}, "n": {solve(ch)}, "r": {"//evil.example/x"}})
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("Location %q", loc)
	}
}

func TestTrustedProxyForwardedFor(t *testing.T) {
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	rg := newRig(t, loopback)
	req, _ := http.NewRequest("GET", rg.srv.URL+"/", nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 127.0.0.2")
	resp, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rg.last().IP != "198.51.100.9" {
		t.Fatalf("ip %s", rg.last().IP)
	}
	if !strings.Contains(string(body), "198.51.100.9, 127.0.0.2, 127.0.0.1") {
		t.Fatalf("upstream XFF chain lost: %q", body)
	}

	// From an untrusted peer the header is ignored.
	plain := newRig(t)
	req2, _ := http.NewRequest("GET", plain.srv.URL+"/", nil)
	req2.Header.Set("X-Forwarded-For", "198.51.100.9")
	resp, _ = http.DefaultClient.Do(req2)
	resp.Body.Close()
	if plain.last().IP != "127.0.0.1" {
		t.Fatalf("untrusted XFF honoured: %s", plain.last().IP)
	}
}

func TestTLSFingerprintReachesEvents(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var got event.Request
	var mu sync.Mutex
	proxy := sensor.NewProxy(sensor.ProxyConfig{Upstream: u, Enforcer: sensor.NewEnforcer(), Emit: func(e event.Request) {
		mu.Lock()
		got = e
		mu.Unlock()
	}})
	srv := httptest.NewUnstartedServer(proxy)
	srv.Listener = sensor.FingerprintListener(srv.Listener)
	srv.Config.ConnContext = sensor.ConnContext
	srv.EnableHTTP2 = true
	srv.TLS = sensor.FingerprintTLS(&tls.Config{}) // StartTLS clones it and adds a cert
	srv.StartTLS()
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if !regexp.MustCompile(`^t13i\d{4}(h2|h1)_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(got.JA4) {
		t.Fatalf("JA4 %q", got.JA4)
	}
}
