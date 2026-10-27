package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dunglas/httpsfv"

	"github.com/AmanamIsrael/lookout/event"
)

// Web Bot Auth: agents sign requests with HTTP Message Signatures (RFC 9421)
// and publish their keys at a well-known directory on their origin.
// Spec: draft-ietf-webbotauth-httpsig-protocol-00 (2026-09-01).

const (
	directoryPath  = "/.well-known/http-message-signatures-directory"
	webBotAuthTag  = "web-bot-auth"
	maxDirectory   = 64 << 10
	maxKeys        = 32
	directoryTTL   = time.Hour
	clockSkew      = time.Minute
	directoryFetch = 5 * time.Second
)

var (
	// ErrNoSignature means the request carries no Web Bot Auth signature.
	ErrNoSignature = errors.New("no web bot auth signature")
	// ErrDirectoryUnavailable means the agent's key directory could not be
	// fetched, so the signature could be neither proven nor disproven.
	ErrDirectoryUnavailable = errors.New("key directory unavailable")
)

// WebBotAuth verifies Web Bot Auth signatures, caching key directories.
type WebBotAuth struct {
	client *http.Client
	mu     sync.Mutex
	dirs   map[string]directory
}

type directory struct {
	keys    map[string]ed25519.PublicKey // by JWK thumbprint
	fetched time.Time
	err     error
}

// NewWebBotAuth returns a verifier. A nil client gets the default: short
// timeouts, no redirects, and no connections to private or loopback
// addresses (the Signature-Agent header is attacker-controlled).
func NewWebBotAuth(client *http.Client) *WebBotAuth {
	if client == nil {
		dialer := &net.Dialer{
			Timeout: directoryFetch,
			Control: func(_, address string, _ syscall.RawConn) error {
				ap, err := netip.ParseAddrPort(address)
				if err != nil {
					return err
				}
				if a := ap.Addr().Unmap(); !a.IsGlobalUnicast() || a.IsPrivate() {
					return fmt.Errorf("refusing to fetch key directory from %s", a)
				}
				return nil
			},
		}
		client = &http.Client{
			Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: directoryFetch},
			Timeout:   directoryFetch,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // the spec forbids following redirects
			},
		}
	}
	return &WebBotAuth{client: client, dirs: map[string]directory{}}
}

// Verify checks the request's signature. It returns the verified agent
// origin, ErrNoSignature, or an error explaining why verification failed.
func (w *WebBotAuth) Verify(ctx context.Context, r event.Request) (string, error) {
	sigInput, sigs, agentHdr := r.Hints["signature-input"], r.Hints["signature"], r.Hints["signature-agent"]
	if sigInput == "" || sigs == "" {
		return "", ErrNoSignature
	}
	inputs, err := httpsfv.UnmarshalDictionary([]string{sigInput})
	if err != nil {
		return "", fmt.Errorf("Signature-Input: %w", err)
	}
	values, err := httpsfv.UnmarshalDictionary([]string{sigs})
	if err != nil {
		return "", fmt.Errorf("Signature: %w", err)
	}

	var lastErr error = ErrNoSignature
	for _, label := range inputs.Names() {
		m, _ := inputs.Get(label)
		il, ok := m.(httpsfv.InnerList)
		if !ok || paramString(il.Params, "tag") != webBotAuthTag {
			continue
		}
		origin, err := w.verifyOne(ctx, r, label, il, values, agentHdr)
		if err == nil {
			return origin, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func (w *WebBotAuth) verifyOne(ctx context.Context, r event.Request, label string, il httpsfv.InnerList, values *httpsfv.Dictionary, agentHdr string) (string, error) {
	sm, ok := values.Get(label)
	if !ok {
		return "", fmt.Errorf("no Signature for label %q", label)
	}
	sigItem, ok := sm.(httpsfv.Item)
	sig, isBytes := sigItem.Value.([]byte)
	if !ok || !isBytes {
		return "", fmt.Errorf("Signature %q is not a byte sequence", label)
	}

	if alg := paramString(il.Params, "alg"); alg != "" && alg != "ed25519" {
		return "", fmt.Errorf("unsupported alg %q", alg)
	}
	created, cok := paramInt(il.Params, "created")
	expires, eok := paramInt(il.Params, "expires")
	if !cok || !eok {
		return "", errors.New("signature lacks created/expires")
	}
	if time.Unix(created, 0).After(r.TS.Add(clockSkew)) || !time.Unix(expires, 0).After(r.TS.Add(-clockSkew)) {
		return "", errors.New("signature not valid at request time")
	}
	keyid := paramString(il.Params, "keyid")
	if keyid == "" {
		return "", errors.New("signature lacks keyid")
	}

	origin, agentLine, err := signatureAgent(agentHdr, label, il)
	if err != nil {
		return "", err
	}

	base, err := signatureBase(r, il, agentLine)
	if err != nil {
		return "", err
	}

	key, err := w.key(ctx, origin, keyid)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(key, []byte(base), sig) {
		return "", fmt.Errorf("signature from %s does not verify", origin)
	}
	return origin, nil
}

// signatureAgent returns the agent origin for label and the serialized value
// to use for the covered "signature-agent" component.
func signatureAgent(hdr, label string, il httpsfv.InnerList) (origin, componentValue string, err error) {
	if hdr == "" {
		return "", "", errors.New("missing Signature-Agent")
	}
	covered := false
	for _, it := range il.Items {
		if name, _ := it.Value.(string); name == "signature-agent" {
			covered = true
		}
	}
	if !covered {
		return "", "", errors.New("Signature-Agent is not covered by the signature")
	}

	var raw string
	if d, err := httpsfv.UnmarshalDictionary([]string{hdr}); err == nil {
		if m, ok := d.Get(label); ok {
			if it, ok := m.(httpsfv.Item); ok {
				raw, _ = it.Value.(string)
				if t := paramString(it.Params, "type"); t != "" && t != "directory" {
					return "", "", fmt.Errorf("Signature-Agent type %q not supported", t)
				}
				componentValue, err = httpsfv.Marshal(it)
				if err != nil {
					return "", "", err
				}
			}
		}
	}
	if raw == "" {
		// Legacy bare-string form, which verifiers MAY accept.
		it, err := httpsfv.UnmarshalItem([]string{hdr})
		if err != nil {
			return "", "", fmt.Errorf("Signature-Agent: %w", err)
		}
		raw, _ = it.Value.(string)
		componentValue = strings.TrimSpace(hdr)
	}

	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "", "", fmt.Errorf("Signature-Agent %q is not an https origin", raw)
	}
	return "https://" + u.Host, componentValue, nil
}

// signatureBase builds the RFC 9421 §2.5 signature base from what the sensor
// recorded. Components the sensor did not keep make verification impossible.
func signatureBase(r event.Request, il httpsfv.InnerList, agentValue string) (string, error) {
	var b strings.Builder
	hasTarget := false
	for _, it := range il.Items {
		name, ok := it.Value.(string)
		if !ok {
			return "", errors.New("component identifier is not a string")
		}
		id, err := httpsfv.Marshal(it)
		if err != nil {
			return "", err
		}
		var v string
		switch name {
		case "@authority":
			v, hasTarget = strings.ToLower(r.Host), true
		case "@method":
			v = r.Method
		case "@path":
			v = r.Path
		case "@query":
			v = "?" + r.Query
		case "@scheme":
			v = scheme(r)
		case "@target-uri":
			v, hasTarget = scheme(r)+"://"+strings.ToLower(r.Host)+r.Path, true
			if r.Query != "" {
				v += "?" + r.Query
			}
		case "signature-agent":
			v = agentValue
		default:
			hv, ok := r.Hints[name]
			if !ok || strings.HasPrefix(name, "@") {
				return "", fmt.Errorf("signature covers %q, which the sensor does not record", name)
			}
			v = hv
		}
		fmt.Fprintf(&b, "%s: %s\n", id, v)
	}
	if !hasTarget {
		return "", errors.New("signature covers neither @authority nor @target-uri")
	}
	params, err := httpsfv.Marshal(httpsfv.List{il})
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", params)
	return b.String(), nil
}

func scheme(r event.Request) string {
	if r.JA4 != "" || r.SNI != "" {
		return "https"
	}
	return "http"
}

func (w *WebBotAuth) key(ctx context.Context, origin, keyid string) (ed25519.PublicKey, error) {
	w.mu.Lock()
	dir, ok := w.dirs[origin]
	w.mu.Unlock()
	if !ok || time.Since(dir.fetched) > directoryTTL || (dir.err != nil && time.Since(dir.fetched) > 5*time.Minute) {
		dir = w.fetch(ctx, origin)
		w.mu.Lock()
		w.dirs[origin] = dir
		w.mu.Unlock()
	}
	if dir.err != nil {
		return nil, dir.err
	}
	k, ok := dir.keys[keyid]
	if !ok {
		return nil, fmt.Errorf("%s publishes no key %s", origin, keyid)
	}
	return k, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
}

func (w *WebBotAuth) fetch(ctx context.Context, origin string) directory {
	dir := directory{keys: map[string]ed25519.PublicKey{}, fetched: time.Now()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+directoryPath, nil)
	if err != nil {
		dir.err = err
		return dir
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json")
	resp, err := w.client.Do(req)
	if err != nil {
		dir.err = fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
		return dir
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dir.err = fmt.Errorf("%w: %s answered %s", ErrDirectoryUnavailable, origin, resp.Status)
		return dir
	}
	var body struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDirectory)).Decode(&body); err != nil {
		dir.err = fmt.Errorf("%w: %s: %v", ErrDirectoryUnavailable, origin, err)
		return dir
	}
	now := time.Now().Unix()
	for _, k := range body.Keys[:min(len(body.Keys), maxKeys)] {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Nbf != 0 && now < k.Nbf) || (k.Exp != 0 && now > k.Exp) {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		dir.keys[Thumbprint(x)] = ed25519.PublicKey(x)
	}
	return dir
}

// Thumbprint is the RFC 7638 / RFC 8037 JWK SHA-256 thumbprint of an Ed25519
// public key, base64url without padding: the Web Bot Auth keyid.
func Thumbprint(pub []byte) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func paramString(p *httpsfv.Params, k string) string {
	if p == nil {
		return ""
	}
	v, _ := p.Get(k)
	s, _ := v.(string)
	return s
}

func paramInt(p *httpsfv.Params, k string) (int64, bool) {
	if p == nil {
		return 0, false
	}
	v, _ := p.Get(k)
	i, ok := v.(int64)
	return i, ok
}
