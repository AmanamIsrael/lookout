package sensor

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AmanamIsrael/lookout/event"
)

// Proxy is a reverse proxy that records every request, applies the active
// decisions and forwards everything else to the upstream app.
type Proxy struct {
	rp         *httputil.ReverseProxy
	enforcer   *Enforcer
	challenger *Challenger
	emit       func(event.Request)
	trusted    []netip.Prefix
}

// ProxyConfig configures NewProxy.
type ProxyConfig struct {
	Upstream *url.URL
	Enforcer *Enforcer
	// Emit receives one event per request. It must not block.
	Emit func(event.Request)
	// TrustedProxies are the CDNs/load balancers whose X-Forwarded-For
	// is believed. Requests from anywhere else use the socket address.
	TrustedProxies []netip.Prefix
}

func NewProxy(cfg ProxyConfig) *Proxy {
	p := &Proxy{
		enforcer:   cfg.Enforcer,
		challenger: NewChallenger(),
		emit:       cfg.Emit,
		trusted:    cfg.TrustedProxies,
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			if p.isTrusted(pr.In.RemoteAddr) {
				pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			}
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("upstream error", "err", err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := p.clientIP(r)
	fp, _ := r.Context().Value(connKey{}).(*fingerprint)
	ja4 := fp.get()
	ev := newRequestEvent(r, ip, ja4, start)

	if r.URL.Path == ChallengePath {
		ev.Action, ev.Status = event.ActionChallenge, http.StatusForbidden
		passed, webdriver := p.challenger.Verify(w, r, ip, start)
		if passed {
			ev.Action, ev.Status = event.ActionChallengePassed, http.StatusSeeOther
		}
		if webdriver {
			ev.Hints["webdriver"] = "1"
		}
		p.finish(ev, start)
		return
	}

	if d, ok := p.enforcer.Match(ip, ja4, start); ok {
		ev.DecisionID = d.ID
		switch d.Kind {
		case event.KindBlock:
			ev.Action, ev.Status = event.ActionBlock, http.StatusForbidden
			http.Error(w, "Forbidden", http.StatusForbidden)
			p.finish(ev, start)
			return
		case event.KindChallenge:
			if !p.challenger.Passed(r, ip, start) {
				ev.Action, ev.Status = event.ActionChallenge, http.StatusForbidden
				p.challenger.Serve(w, r, ip, start)
				p.finish(ev, start)
				return
			}
		case event.KindRateLimit:
			if !p.enforcer.Allow(d, ip, start) {
				ev.Action, ev.Status = event.ActionRateLimit, http.StatusTooManyRequests
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				p.finish(ev, start)
				return
			}
		}
	}

	cw := &captureWriter{ResponseWriter: w}
	body := &countingReader{ReadCloser: r.Body}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = body
	}
	p.rp.ServeHTTP(cw, r)
	ev.Status = cw.status
	if ev.Status == 0 {
		ev.Status = http.StatusOK
	}
	ev.BytesIn, ev.BytesOut = body.n, cw.n
	p.finish(ev, start)
}

func (p *Proxy) finish(ev event.Request, start time.Time) {
	ev.DurationMS = float64(time.Since(start).Microseconds()) / 1000
	p.emit(ev)
}

func newRequestEvent(r *http.Request, ip, ja4 string, now time.Time) event.Request {
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	slices.Sort(names)
	hints := map[string]string{}
	for _, h := range event.HintHeaders {
		if v := r.Header.Get(h); v != "" {
			hints[h] = clip(v, 1024)
		}
	}
	ev := event.Request{
		TS:      now.UTC(),
		IP:      ip,
		Method:  clip(r.Method, 16),
		Host:    clip(r.Host, 255),
		Path:    clip(r.URL.Path, 2048),
		Query:   clip(redactQuery(r.URL.RawQuery), 2048),
		Proto:   r.Proto,
		UA:      clip(r.UserAgent(), 512),
		Referer: clip(r.Referer(), 512),
		Headers: names[:min(len(names), 64)],
		Hints:   hints,
		JA4:     ja4,
		Action:  event.ActionAllow,
	}
	if r.TLS != nil {
		ev.SNI = r.TLS.ServerName
	}
	return ev
}

var sensitiveParam = regexp.MustCompile(`(?i)(pass|pwd|secret|token|key|auth|session|sig|code|jwt|cookie|credential)`)

// redactQuery blanks the values of parameters whose names look sensitive,
// keeping the rest so injection attempts stay visible.
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		name, _, hasValue := strings.Cut(part, "=")
		if hasValue && sensitiveParam.MatchString(name) {
			parts[i] = name + "=[redacted]"
		}
	}
	return strings.Join(parts, "&")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (p *Proxy) isTrusted(remoteAddr string) bool {
	addr, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	return p.trustedAddr(addr.Addr())
}

func (p *Proxy) trustedAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, pre := range p.trusted {
		if pre.Contains(a) {
			return true
		}
	}
	return false
}

// clientIP is the socket address unless it is a trusted proxy, in which case
// it is the right-most X-Forwarded-For entry that is not itself trusted.
func (p *Proxy) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !p.trustedAddr(addr) {
		return host
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		if !p.trustedAddr(hop) {
			return hop.Unmap().String()
		}
	}
	return addr.Unmap().String()
}

// captureWriter records the status code and response size. Unwrap lets
// http.ResponseController reach Flush and Hijack (streaming, WebSockets).
type captureWriter struct {
	http.ResponseWriter
	status int
	n      int64
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

type countingReader struct {
	io.ReadCloser
	n int64
}

func (c *countingReader) Read(b []byte) (int, error) {
	n, err := c.ReadCloser.Read(b)
	c.n += int64(n)
	return n, err
}

// --- TLS fingerprint plumbing ---------------------------------------------
//
// The JA4 is computed once per connection during the handshake and read by
// every request on that connection through the request context.

type connKey struct{}

type fingerprint struct{ ja4 atomic.Pointer[string] }

func (f *fingerprint) get() string {
	if f == nil {
		return ""
	}
	if s := f.ja4.Load(); s != nil {
		return *s
	}
	return ""
}

type fpConn struct {
	net.Conn
	fp *fingerprint
}

type fpListener struct{ net.Listener }

func (l fpListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fpConn{Conn: c, fp: &fingerprint{}}, nil
}

// FingerprintListener wraps l so each connection can carry its JA4.
func FingerprintListener(l net.Listener) net.Listener { return fpListener{l} }

// FingerprintTLS returns a copy of base that records the JA4 of each
// ClientHello on connections accepted through FingerprintListener.
func FingerprintTLS(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	next := base.GetConfigForClient
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if c, ok := hello.Conn.(*fpConn); ok {
			ja4 := JA4(hello)
			c.fp.ja4.CompareAndSwap(nil, &ja4) // keep the first hello after a HelloRetryRequest
		}
		if next != nil {
			return next(hello)
		}
		return nil, nil
	}
	return cfg
}

// ConnContext is the http.Server ConnContext hook that exposes the JA4.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if fc, ok := c.(*fpConn); ok {
		return context.WithValue(ctx, connKey{}, fc.fp)
	}
	return ctx
}
