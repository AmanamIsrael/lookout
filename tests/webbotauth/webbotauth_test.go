package webbotauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AmanamIsrael/lookout/event"
	"github.com/AmanamIsrael/lookout/server/verify"
)

type agent struct {
	priv   ed25519.PrivateKey
	keyid  string
	origin string // https://127.0.0.1:port
	srv    *httptest.Server
}

func newAgent(t *testing.T) *agent {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &agent{priv: priv, keyid: verify.Thumbprint(pub)}
	x := base64.RawURLEncoding.EncodeToString(pub)
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/http-message-signatures-directory" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":%q,"x":%q}]}`, a.keyid, x)
	}))
	t.Cleanup(a.srv.Close)
	a.origin = a.srv.URL
	return a
}

// sign builds the request the way a Web Bot Auth agent would. The signature
// base is written out by hand from RFC 9421 §2.5, independent of the verifier.
func (a *agent) sign(host string, created, expires time.Time) event.Request {
	params := fmt.Sprintf(`("@authority" "signature-agent";key="sig1");created=%d;keyid="%s";alg="ed25519";expires=%d;tag="web-bot-auth"`,
		created.Unix(), a.keyid, expires.Unix())
	agentValue := fmt.Sprintf("%q", a.origin)
	base := `"@authority": ` + host + "\n" +
		`"signature-agent";key="sig1": ` + agentValue + "\n" +
		`"@signature-params": ` + params
	sig := ed25519.Sign(a.priv, []byte(base))
	return event.Request{
		TS: time.Now(), IP: "198.51.100.4", Method: "GET", Host: host, Path: "/", JA4: "t13d1516h2_x_y",
		Hints: map[string]string{
			"signature-agent": "sig1=" + agentValue,
			"signature-input": "sig1=" + params,
			"signature":       "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":",
		},
	}
}

func TestValidSignatureVerifies(t *testing.T) {
	a := newAgent(t)
	v := verify.NewWebBotAuth(a.srv.Client())
	now := time.Now()
	origin, err := v.Verify(context.Background(), a.sign("example.com", now.Add(-time.Minute), now.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if origin != a.origin {
		t.Fatalf("origin %s, want %s", origin, a.origin)
	}
}

func TestTamperedAuthorityFails(t *testing.T) {
	a := newAgent(t)
	v := verify.NewWebBotAuth(a.srv.Client())
	now := time.Now()
	r := a.sign("example.com", now.Add(-time.Minute), now.Add(time.Hour))
	r.Host = "victim.example" // replayed against another site
	if _, err := v.Verify(context.Background(), r); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("err = %v", err)
	}
}

func TestExpiredSignatureFails(t *testing.T) {
	a := newAgent(t)
	v := verify.NewWebBotAuth(a.srv.Client())
	now := time.Now()
	r := a.sign("example.com", now.Add(-2*time.Hour), now.Add(-time.Hour))
	if _, err := v.Verify(context.Background(), r); err == nil || !strings.Contains(err.Error(), "not valid at request time") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownKeyFails(t *testing.T) {
	a, b := newAgent(t), newAgent(t)
	now := time.Now()
	r := b.sign("example.com", now.Add(-time.Minute), now.Add(time.Hour))
	// Claim a's directory while signing with b's key.
	r.Hints["signature-agent"] = fmt.Sprintf("sig1=%q", a.origin)
	v := verify.NewWebBotAuth(a.srv.Client())
	if _, err := v.Verify(context.Background(), r); err == nil {
		t.Fatal("signature with a key the directory does not publish verified")
	}
}

func TestNoSignature(t *testing.T) {
	v := verify.NewWebBotAuth(nil)
	_, err := v.Verify(context.Background(), event.Request{Hints: map[string]string{}})
	if !errors.Is(err, verify.ErrNoSignature) {
		t.Fatalf("err = %v", err)
	}
}

// The Signature-Agent header is attacker-controlled; the default client must
// not fetch from loopback or private addresses.
func TestDefaultClientRefusesPrivateAddresses(t *testing.T) {
	a := newAgent(t)
	now := time.Now()
	v := verify.NewWebBotAuth(nil)
	_, err := v.Verify(context.Background(), a.sign("example.com", now.Add(-time.Minute), now.Add(time.Hour)))
	if !errors.Is(err, verify.ErrDirectoryUnavailable) || !strings.Contains(err.Error(), "refusing to fetch") {
		t.Fatalf("err = %v", err)
	}
}
