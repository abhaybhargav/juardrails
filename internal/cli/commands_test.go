package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCredentialRequiresPrivateServiceFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode test; Windows ACLs are tested in securefile")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".juardrails")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte(`{"url":"http://127.0.0.1:8080","token":"secret"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(); err == nil {
		t.Fatal("accepted public credential")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"url":"http://example.com","token":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredential(); err == nil {
		t.Fatal("accepted remote plaintext URL")
	}
}
func TestClientRejectsHumanSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing service credential")
		}
		w.Write([]byte(`{"principal":{"kind":"human"},"token_kind":"session"}`))
	}))
	defer server.Close()
	c := client{base: server.URL, token: "secret", namespace: "root", http: server.Client()}
	if err := c.requireService(); err == nil || !strings.Contains(err.Error(), "service account") {
		t.Fatal(err)
	}
}
