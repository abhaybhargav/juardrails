package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/config"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
	"github.com/abhaybhargav/juardrails/internal/securefile"
)

// bootstrapCLI provisions the local server and one explicitly privileged CLI service account.
// The generated secret is written once and never printed to a terminal.
func bootstrapCLI(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	dbPath := fs.String("db", "data/juardrails.sqlite", "SQLite database path")
	auditPath := fs.String("audit-log", "data/audit.jsonl", "audit file path")
	serverURL := fs.String("url", "http://127.0.0.1:8080", "URL used by the local CLI")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected bootstrap arguments")
	}
	u, err := url.Parse(*serverURL)
	if err != nil {
		return err
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopback)) {
		return fmt.Errorf("CLI URL must use HTTPS (HTTP is allowed only on loopback)")
	}
	if err := config.LoadEnv(".env"); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".juardrails")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("credential directory is not a real directory: %s", dir)
	}
	if err = securefile.Protect(dir); err != nil {
		return fmt.Errorf("protect credential directory: %w", err)
	}
	if err = securefile.Check(dir, true); err != nil {
		return err
	}
	path := filepath.Join(dir, "credentials.json")
	if _, err = os.Lstat(path); err == nil {
		return fmt.Errorf("credential already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	log, err := audit.Open(*auditPath)
	if err != nil {
		return err
	}
	defer log.Close()
	store, err := guardrail.Open(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if *dbPath == "data/juardrails.sqlite" {
		if _, statErr := os.Stat("data/juardrails.db"); statErr == nil {
			pending, checkErr := store.LegacyImportPending()
			if checkErr != nil {
				return checkErr
			}
			if pending {
				if err := store.ImportBolt("data/juardrails.db"); err != nil {
					return err
				}
				if err := log.Write(audit.Event{Phase: "system", Action: "database:migrated"}); err != nil {
					return err
				}
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
	}
	auth, err := access.New(store.DB())
	if err != nil {
		return err
	}
	if err = bootstrap(auth, filepath.Join(filepath.Dir(*dbPath), "bootstrap-admin.json"), log); err != nil {
		return err
	}
	const account = "cli-admin"
	var principal access.Principal
	principals, err := auth.Principals()
	if err != nil {
		return err
	}
	for _, p := range principals {
		if p.Name == account {
			if p.Kind != "service" || p.Disabled {
				return fmt.Errorf("%s already exists but is not an active service account", account)
			}
			principal = p
			break
		}
	}
	if principal.ID == "" {
		principal, err = auth.CreatePrincipal(account, "service", "Local CLI administrator", "")
		if err != nil {
			return err
		}
	}
	const grant = "cli-administration"
	if _, err = auth.Policy(grant); err != nil {
		if err != access.ErrNotFound {
			return err
		}
		_, err = auth.SavePolicy(access.Policy{Name: grant, Description: "Explicit CLI administration and policy access", Rules: []access.Rule{{Namespace: "*", Actions: append(append([]string{}, access.Actions...), "admin:manage")}}}, true)
		if err != nil {
			return err
		}
	}
	if err = auth.Bind(principal.ID, []string{grant}); err != nil {
		return err
	}
	if !auth.AllowedAdmin(principal) {
		return fmt.Errorf("existing %s policy does not grant admin:manage; inspect it before bootstrapping", grant)
	}
	for _, action := range access.Actions {
		if !auth.Allowed(principal, "root", action) {
			return fmt.Errorf("existing %s policy does not grant %s", grant, action)
		}
	}
	metadata, raw, err := auth.IssueServiceToken(principal.ID, "local-cli", time.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}{*serverURL, raw}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = securefile.Protect(path); err == nil {
		err = securefile.Check(path, false)
	}
	if err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("protect service credential: %w", err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return err
	}
	if err = log.Write(audit.Event{Phase: "system", Action: "cli:bootstrap", ActorID: principal.ID, Actor: principal.Name, ActorKind: "service", TokenID: metadata.ID}); err != nil {
		return err
	}
	fmt.Printf("Server initialized. CLI service credential: %s\nStart with: juardrails -db %s -audit-log %s\n", path, *dbPath, *auditPath)
	return nil
}
