package server

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/abhaybhargav/juardrails/internal/skillgen"
)

func TestSkillGenerationRequiresPolicyReadAndProducesDownload(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provided-key" {
			t.Error("wrong provider credential")
		}
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"description\":\"Evaluate support responses with the saved Juardrails guardrail policy.\",\"use_when\":\"Use this policy before sending a support response to a customer.\"}"}}]}`))
	}))
	defer provider.Close()
	app, h := testServer(t, "", false)
	app.SkillAI = skillgen.Builder{Endpoint: provider.URL + "/chat/completions"}
	source, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte(`"status": "draft"`), []byte(`"status": "active"`), 1)
	if w := request(h, "POST", "/api/v1/policies", string(source)); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	path := "/api/v1/policies/support-safety/skill"
	if w := request(h, "POST", path, `{}`); w.Code != 409 {
		t.Fatal("missing key accepted", w.Code)
	}
	w := request(h, "POST", path, `{"api_key":"provided-key","model":"test-model"}`)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" || w.Header().Get("X-Juardrails-Skill-Name") == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len())); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "provided-key") {
		t.Fatal("provider key leaked into download")
	}
	other, err := app.Auth.CreatePrincipal("no-policy-access", "human", "", "another-long-password")
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Login(other.Name, "another-long-password", "test")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"api_key":"provided-key"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+session.Secret)
	w = httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("policy read denial bypassed", w.Code)
	}
}
