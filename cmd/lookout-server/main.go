// lookout-server collects sensor data, scores and triages actors, and serves
// the dashboard.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/AmanamIsrael/lookout/server"
	"github.com/AmanamIsrael/lookout/server/store"
	"github.com/AmanamIsrael/lookout/server/triage"
	"github.com/AmanamIsrael/lookout/server/verify"
	"github.com/AmanamIsrael/lookout/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// triager picks the LLM provider from whichever API key is set.
func triager() (*triage.Triager, error) {
	openrouter, anthropic := os.Getenv("OPENROUTER_API_KEY"), os.Getenv("ANTHROPIC_API_KEY")
	effort := env("LOOKOUT_LLM_EFFORT", "medium")
	switch {
	case openrouter != "" && anthropic != "":
		return nil, errors.New("both OPENROUTER_API_KEY and ANTHROPIC_API_KEY are set; unset one so triage uses a single provider")
	case openrouter != "":
		return triage.NewOpenRouter(env("LOOKOUT_OPENROUTER_URL", triage.OpenRouterURL), openrouter,
			env("LOOKOUT_LLM_MODEL", "deepseek/deepseek-v4.1-flash"), effort), nil
	case anthropic != "":
		return triage.NewAnthropic(anthropic, env("LOOKOUT_LLM_MODEL", "claude-opus-5-5"), effort), nil
	}
	return nil, nil
}

func run() error {
	token := os.Getenv("LOOKOUT_ADMIN_TOKEN")
	if len(token) < 16 {
		return errors.New("set LOOKOUT_ADMIN_TOKEN to a random string of at least 16 characters (e.g. `openssl rand -hex 24`)")
	}

	st, err := store.Open(env("LOOKOUT_DB", "lookout.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	cfg := server.DefaultConfig()
	cfg.TriagePerHour = envInt("LOOKOUT_TRIAGE_PER_HOUR", cfg.TriagePerHour)
	cfg.TriageMinScore = envInt("LOOKOUT_TRIAGE_MIN_SCORE", cfg.TriageMinScore)
	cfg.Retention = time.Duration(envInt("LOOKOUT_RETENTION_DAYS", 7)) * 24 * time.Hour

	t, err := triager()
	if err != nil {
		return err
	}
	if t != nil {
		slog.Info("LLM triage on", "model", t.Model(), "per_hour", cfg.TriagePerHour)
	} else {
		slog.Info("LLM triage off: set OPENROUTER_API_KEY or ANTHROPIC_API_KEY to turn it on; rules still score and suggest")
	}

	engine := server.NewEngine(cfg, st, verify.New(verify.NewWebBotAuth(nil), net.DefaultResolver), t)
	api := server.NewAPI(st, engine, token, web.UI())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go engine.Run(ctx)

	srv := &http.Server{
		Addr:              env("LOOKOUT_ADDR", "127.0.0.1:8080"),
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("lookout-server listening", "addr", srv.Addr)
		errc <- srv.ListenAndServe()
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
