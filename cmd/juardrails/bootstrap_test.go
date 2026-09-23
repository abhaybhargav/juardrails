package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

func TestBootstrapProvisionsCLIService(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("JUARDRAILS_ADMIN_PASSWORD", "test-password-long")
	db := filepath.Join(root, "data", "app.sqlite")
	audit := filepath.Join(root, "data", "audit.jsonl")
	if err := bootstrapCLI([]string{"-db", db, "-audit-log", audit}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".juardrails", "credentials.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("credential mode %o", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	if err = json.Unmarshal(data, &credential); err != nil {
		t.Fatal(err)
	}
	if credential.URL != "http://127.0.0.1:8080" || credential.Token == "" {
		t.Fatal("invalid credential")
	}
	store, err := guardrail.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	auth, err := access.New(store.DB())
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Authenticate(credential.Token)
	if err != nil {
		t.Fatal(err)
	}
	if session.Principal.Kind != "service" || !auth.AllowedAdmin(session.Principal) || !auth.Allowed(session.Principal, "root", "policies:create") {
		t.Fatal("bootstrap grants missing")
	}
	if err = bootstrapCLI([]string{"-db", db, "-audit-log", audit}); err == nil {
		t.Fatal("overwrote service credential")
	}
}
