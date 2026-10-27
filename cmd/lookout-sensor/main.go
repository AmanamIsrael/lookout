// lookout-sensor sits in front of an app as a reverse proxy, records every
// request (with its TLS fingerprint), optionally records outbound
// connections with eBPF, ships both to lookout-server and enforces the
// decisions you approve there.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/AmanamIsrael/lookout/sensor"
	"github.com/AmanamIsrael/lookout/sensor/egress"
)

func main() {
	if err := run(); err != nil {
		slog.Error("sensor stopped", "err", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run() error {
	var (
		listen     = flag.String("listen", env("LOOKOUT_LISTEN", ":8443"), "address to accept traffic on")
		upstream   = flag.String("upstream", env("LOOKOUT_UPSTREAM", ""), "app to forward to, e.g. http://127.0.0.1:3000")
		server     = flag.String("server", env("LOOKOUT_SERVER", ""), "lookout-server URL")
		certFile   = flag.String("tls-cert", env("LOOKOUT_TLS_CERT", ""), "TLS certificate file")
		keyFile    = flag.String("tls-key", env("LOOKOUT_TLS_KEY", ""), "TLS private key file")
		domains    = flag.String("domain", env("LOOKOUT_DOMAIN", ""), "comma-separated domains for automatic Let's Encrypt certificates")
		acmeCache  = flag.String("acme-cache", env("LOOKOUT_ACME_CACHE", "lookout-certs"), "directory for automatic certificates")
		trust      = flag.String("trust-proxy", env("LOOKOUT_TRUST_PROXY", ""), "comma-separated CIDRs whose X-Forwarded-For is trusted")
		withEgress = flag.Bool("egress", env("LOOKOUT_EGRESS", "") == "1", "record outbound connections with eBPF (needs root or CAP_BPF+CAP_PERFMON)")
		loopback   = flag.Bool("egress-loopback", false, "also record connections to loopback")
	)
	flag.Parse()
	key := os.Getenv("LOOKOUT_KEY") // env only, so it never shows up in `ps`
	if *upstream == "" || *server == "" || key == "" {
		return errors.New("set -upstream, -server and the LOOKOUT_KEY environment variable")
	}
	up, err := url.Parse(*upstream)
	if err != nil || up.Scheme == "" || up.Host == "" {
		return fmt.Errorf("bad -upstream %q", *upstream)
	}
	trusted, err := parsePrefixes(*trust)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shipCtx, stopShipping := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() {
		stopShipping() // flushes the last batch
		wg.Wait()
	}()

	shipper := sensor.NewShipper(*server, key)
	enforcer := sensor.NewEnforcer()
	wg.Go(func() { shipper.Run(shipCtx) })
	wg.Go(func() { shipper.PollDecisions(shipCtx, enforcer) })

	if *withEgress {
		wg.Go(func() {
			if err := egress.Run(shipCtx, egress.Options{Loopback: *loopback}, shipper.EmitEgress); err != nil {
				slog.Error("egress capture disabled", "err", err)
			}
		})
	}

	proxy := sensor.NewProxy(sensor.ProxyConfig{
		Upstream:       up,
		Enforcer:       enforcer,
		Emit:           shipper.EmitRequest,
		TrustedProxies: trusted,
	})
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext:       sensor.ConnContext,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ln = sensor.FingerprintListener(ln)

	var tlsCfg *tls.Config
	switch {
	case *domains != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(strings.Split(*domains, ",")...),
			Cache:      autocert.DirCache(*acmeCache),
		}
		tlsCfg = m.TLSConfig()
	case *certFile != "" && *keyFile != "":
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	errc := make(chan error, 1)
	go func() {
		if tlsCfg == nil {
			slog.Warn("serving plain HTTP: no TLS fingerprints. Use -tls-cert/-tls-key or -domain")
			slog.Info("sensor listening", "addr", ln.Addr().String(), "upstream", up.String())
			errc <- srv.Serve(ln)
			return
		}
		srv.TLSConfig = sensor.FingerprintTLS(tlsCfg)
		slog.Info("sensor listening (TLS)", "addr", ln.Addr().String(), "upstream", up.String())
		errc <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case err = <-errc:
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = srv.Shutdown(shutdown)
		cancel()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			a, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("bad -trust-proxy %q", part)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("bad -trust-proxy %q", part)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
