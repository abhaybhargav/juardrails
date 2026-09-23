package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/config"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
	"github.com/abhaybhargav/juardrails/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	dbPath := flag.String("db", "data/juardrails.sqlite", "SQLite database path")
	auditPath := flag.String("audit-log", "data/audit.jsonl", "append-only JSON audit file")
	legacy := flag.String("migrate-bbolt", "", "import an existing bbolt database into an empty SQLite database")
	flag.Parse()
	if err := config.LoadEnv(".env"); err != nil {
		slog.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	auditLog, err := audit.Open(*auditPath)
	if err != nil {
		slog.Error("open audit log", "error", err)
		os.Exit(1)
	}
	defer auditLog.Close()
	if err = auditLog.Write(audit.Event{Phase: "system", Action: "startup"}); err != nil {
		slog.Error("audit unavailable", "error", err)
		os.Exit(1)
	}
	store, err := guardrail.Open(*dbPath)
	if err != nil {
		slog.Error("open database", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	if *dbPath == "data/juardrails.sqlite" && *legacy == "" {
		if _, e := os.Stat("data/juardrails.db"); e == nil {
			pending, e := store.LegacyImportPending()
			if e != nil {
				slog.Error("check import state", "error", e)
				os.Exit(1)
			}
			if pending {
				*legacy = "data/juardrails.db"
			}
		}
	}

	if *legacy != "" {
		if err = store.ImportBolt(*legacy); err != nil {
			slog.Error("legacy import failed; source retained", "error", err)
			os.Exit(1)
		}
		if err = auditLog.Write(audit.Event{Phase: "system", Action: "database:migrated"}); err != nil {
			slog.Error("audit migration", "error", err)
			os.Exit(1)
		}
	}
	provider, err := config.ProviderFromEnv(os.Getenv)
	if err != nil {
		slog.Error("invalid provider configuration", "error", err)
		os.Exit(1)
	}
	jev := &guardrail.Jev{APIKey: provider.APIKey, Endpoint: provider.Endpoint, Format: provider.Format, DefaultModel: provider.DefaultModel}
	app, err := server.New(store, jev, auditLog, provider.APIKey != "")
	if err != nil {
		slog.Error("initialize access control", "error", err)
		os.Exit(1)
	}
	app.SecureCookies = os.Getenv("JUARDRAILS_COOKIE_SECURE") == "true"
	if err = bootstrap(app.Auth, filepath.Join(filepath.Dir(*dbPath), "bootstrap-admin.json"), auditLog); err != nil {
		slog.Error("bootstrap admin", "error", err)
		os.Exit(1)
	}
	app.Provider = provider

	srv := &http.Server{Addr: *addr, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			slog.Error("shutdown", "error", err)
		}
	}()
	slog.Info("Juardrails listening", "url", "http://"+*addr, "live_jev", provider.APIKey != "", "authentication", true)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
	<-shutdownDone
	if err := auditLog.Write(audit.Event{Phase: "system", Action: "shutdown"}); err != nil {
		slog.Error("audit shutdown", "error", err)
	}
}

// Bootstrap only once. The protected file also allows retry after an interrupted first startup.
func bootstrap(auth *access.Manager, path string, log *audit.Logger) error {
	needed, err := auth.NeedsBootstrap()
	if err != nil || !needed {
		return err
	}
	cfg := struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{os.Getenv("JUARDRAILS_ADMIN_USER"), os.Getenv("JUARDRAILS_ADMIN_PASSWORD")}
	if cfg.Username == "" {
		cfg.Username = "admin"
	}
	if cfg.Password == "" {
		if b, err := os.ReadFile(path); err == nil {
			if err = json.Unmarshal(b, &cfg); err != nil {
				return err
			}
		} else if os.IsNotExist(err) {
			cfg.Password = access.GenerateSecret()
			b, _ := json.MarshalIndent(cfg, "", "  ")
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = f.Write(b)
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		} else {
			return err
		}
		slog.Info("initial administrator credentials saved", "file", path)
	}
	if err = log.Write(audit.Event{Phase: "system", Action: "admin:bootstrap-attempt"}); err != nil {
		return err
	}
	p, err := auth.Bootstrap(cfg.Username, cfg.Password)
	if err != nil {
		return fmt.Errorf("create initial admin: %w", err)
	}
	return log.Write(audit.Event{Phase: "system", Action: "admin:bootstrapped", ActorID: p.ID, Actor: p.Name, ActorKind: "human"})
}
