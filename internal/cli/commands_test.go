package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
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

func TestSkillCommandUsesServiceCredentialAndPreservesExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX credential permissions are covered here; Windows ACLs are tested in securefile")
	}
	archive := new(bytes.Buffer)
	z := zip.NewWriter(archive)
	w, err := z.Create("juardrails-root-sample/SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("---\nname: juardrails-root-sample\ndescription: Sample\n---\n"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer service-secret" || r.Header.Get("X-Juardrails-Namespace") != "root" {
			t.Error("missing service credential or namespace")
		}
		switch r.URL.Path {
		case "/api/v1/auth/me":
			w.Write([]byte(`{"principal":{"kind":"service"},"token_kind":"service"}`))
		case "/api/v1/policies/sample/skill":
			var body struct {
				APIKey string `json:"api_key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.APIKey != "generation-key" {
				t.Error("generation key was not sent", err)
			}
			w.Write(archive.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SKILL_AI_API_KEY", "generation-key")
	dir := filepath.Join(home, ".juardrails")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	credential, _ := json.Marshal(map[string]string{"url": server.URL, "token": "service-secret"})
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), credential, 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "skill.zip")
	if err := Run([]string{"skill", "sample", path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, archive.Bytes()) {
		t.Fatal("skill archive was not saved unchanged", err)
	}
	if err := Run([]string{"skill", "sample", path}); err == nil {
		t.Fatal("existing skill archive was overwritten")
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
