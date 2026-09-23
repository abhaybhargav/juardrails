package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

func testServer(t *testing.T, token string, live bool) (*Server, http.Handler) {
	t.Helper()
	s, err := guardrail.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	app, err := New(s, &guardrail.Jev{}, log, live)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.Auth.Bootstrap("admin", "test-password-long"); err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Login("admin", "test-password-long", "test")
	if err != nil {
		t.Fatal(err)
	}
	h := app.Handler()
	if token != "" {
		return app, h
	}
	return app, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+session.Secret)
		h.ServeHTTP(w, r)
	})
}
func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestPolicyLifecycleAndSimulation(t *testing.T) {
	app, h := testServer(t, "", false)
	policy, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	sim, err := os.ReadFile("../../examples/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	r := request(h, "POST", "/api/v1/policies", string(policy))
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	var p guardrail.Policy
	json.Unmarshal(r.Body.Bytes(), &p)
	if r = request(h, "POST", "/api/v1/policies", string(policy)); r.Code != 409 {
		t.Fatal(r.Code)
	}
	if r = request(h, "POST", "/api/v1/policies/support-safety/simulate", string(sim)); r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var eval guardrail.Evaluation
	json.Unmarshal(r.Body.Bytes(), &eval)
	if eval.Decision != "allow" || eval.Source != "simulation" || eval.PolicyVersion != 1 {
		t.Fatal(eval)
	}
	r = request(h, "GET", "/api/v1/evaluations/"+eval.ID, "")
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	if bytes.Contains(r.Body.Bytes(), []byte("My order arrived")) {
		t.Fatal("state leaked into history")
	}
	r = request(h, "POST", "/api/v1/policies/support-safety/evaluate", `{"state":"test"}`)
	if r.Code != 409 {
		t.Fatal(r.Code)
	}
	p.Status = "active"
	b, _ := json.Marshal(p)
	r = request(h, "PUT", "/api/v1/policies/support-safety", string(b))
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	r = request(h, "PUT", "/api/v1/policies/support-safety", string(b))
	if r.Code != 409 {
		t.Fatal(r.Code)
	}
	r = request(h, "POST", "/api/v1/policies/support-safety/evaluate", `{"state":"test"}`)
	if r.Code != 503 {
		t.Fatal(r.Code)
	}
	r = request(h, "POST", "/api/v1/policies/support-safety/simulate", `{"state":"test","answers":{"intent":{"type":"choice"}}}`)
	if r.Code != 422 {
		t.Fatal(r.Code)
	}
	json.Unmarshal(r.Body.Bytes(), &eval)
	if eval.Decision != "error" {
		t.Fatal(eval)
	}
	records, err := app.Store.Evaluations("support-safety", 10)
	if err != nil || len(records) != 2 {
		t.Fatal(records, err)
	}
	r = request(h, "GET", "/api/v1/policies/support-safety/revisions", "")
	if r.Code != 200 {
		t.Fatal(r.Code)
	}
	r = request(h, "DELETE", "/api/v1/policies/support-safety?version=2", "")
	if r.Code != 204 {
		t.Fatal(r.Code)
	}
	r = request(h, "GET", "/api/v1/policies/support-safety", "")
	if r.Code != 404 {
		t.Fatal(r.Code)
	}
}
func TestRequestValidationAndAuthentication(t *testing.T) {
	app, h := testServer(t, "test-secret", false)
	session, err := app.Auth.Login("admin", "test-password-long", "test")
	if err != nil {
		t.Fatal(err)
	}
	if w := request(h, "GET", "/api/v1/policies", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, basic := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/api/v1/policies", nil)
		if basic {
			r.SetBasicAuth("admin", "test-secret")
		} else {
			r.Header.Set("Authorization", "Bearer "+session.Secret)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if (!basic && w.Code != 200) || (basic && w.Code != 401) {
			t.Fatal(w.Code)
		}
	}
	if w := request(h, "GET", "/healthz", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	_, h = testServer(t, "", false)
	for _, body := range []string{`{"unknown":1}`, `{} {}`, `null`, strings.Repeat("x", 1048577)} {
		w := request(h, "POST", "/api/v1/policies", body)
		if w.Code < 400 {
			t.Fatalf("accepted %s", body[:min(20, len(body))])
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/policies", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("POST", "/api/v1/policies", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin request allowed", w.Code)
	}
}
func TestPagesAndOpenAPI(t *testing.T) {
	_, h := testServer(t, "", false)
	for _, path := range []string{"/", "/policies/new", "/playground", "/evaluations", "/docs", "/access", "/account", "/login", "/static/app.css", "/static/app.js", "/api/v1/openapi.json"} {
		w := request(h, "GET", path, "")
		if w.Code != 200 || w.Body.Len() == 0 {
			t.Fatal(path, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing CSP")
		}
	}
	w := request(h, "GET", "/api/v1/openapi.json", "")
	var spec map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if spec["openapi"] != "3.1.0" {
		t.Fatal(spec["openapi"])
	}
}

func TestLiveProviderIntegrationAndFailureAudit(t *testing.T) {
	app, h := testServer(t, "", true)
	source, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	var p guardrail.Policy
	if err = json.Unmarshal(source, &p); err != nil {
		t.Fatal(err)
	}
	p.Status = "active"
	p, err = app.Store.Save(p, true)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../examples/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Answers map[string]guardrail.Answer `json:"answers"`
	}
	if err = json.Unmarshal(fixture, &req); err != nil {
		t.Fatal(err)
	}
	bad := false
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			State     any                           `json:"state"`
			Questions map[string]guardrail.Question `json:"questions"`
			Model     string                        `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.State != "sample state" || len(body.Questions) != 3 {
			t.Error("state/questions not forwarded")
		}
		if bad {
			json.NewEncoder(w).Encode(map[string]any{"model": "jev-test", "answers": map[string]any{}})
			return
		}
		json.NewEncoder(w).Encode(guardrail.JevResponse{Model: "jev-test", Answers: req.Answers, Usage: map[string]int{"input_tokens": 123}})
	}))
	defer provider.Close()
	app.Jev = &guardrail.Jev{APIKey: "test", BaseURL: provider.URL, Client: provider.Client()}
	w := request(h, "POST", "/api/v1/policies/"+p.ID+"/evaluate", `{"state":"sample state"}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var e guardrail.Evaluation
	json.Unmarshal(w.Body.Bytes(), &e)
	if e.Source != "jev" || e.Model != "jev-test" || e.Decision != "allow" || e.Usage["input_tokens"] != 123 {
		t.Fatal(e)
	}
	bad = true
	w = request(h, "POST", "/api/v1/policies/"+p.ID+"/evaluate", `{"state":"sample state"}`)
	if w.Code != 502 {
		t.Fatal(w.Code, w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &e)
	if e.Decision != "error" || e.Error == "" {
		t.Fatal(e)
	}
	history, err := app.Store.Evaluations(p.ID, 100)
	if err != nil || len(history) != 2 {
		t.Fatal(history, err)
	}
	w = request(h, "POST", "/api/v1/policies/"+p.ID+"/evaluate", string(fixture))
	if w.Code != 422 {
		t.Fatal("live endpoint accepted caller-supplied answers")
	}
}

func TestYAMLRESTLifecycle(t *testing.T) {
	_, h := testServer(t, "", false)
	body, err := os.ReadFile("../../examples/support-safety.yaml")
	if err != nil {
		t.Fatal(err)
	}
	yamlRequest := func(method, path string, b []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/yaml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := yamlRequest("POST", "/api/v1/policies/validate", body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = yamlRequest("POST", "/api/v1/policies", body)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(h, "GET", "/api/v1/policies/support-safety?format=yaml", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/yaml" {
		t.Fatal(w.Code, w.Header())
	}
	p, err := guardrail.DecodePolicy(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 {
		t.Fatal(p.Version)
	}
	p.Name = "Updated from YAML"
	encoded, err := guardrail.MarshalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	w = yamlRequest("PUT", "/api/v1/policies/support-safety", encoded)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = yamlRequest("PUT", "/api/v1/policies/support-safety", encoded)
	if w.Code != 409 {
		t.Fatal("stale YAML revision accepted")
	}
	r := httptest.NewRequest("GET", "/api/v1/policies/support-safety", nil)
	r.Header.Set("Accept", "application/yaml")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	p, err = guardrail.DecodePolicy(w.Body.Bytes())
	if err != nil || p.Version != 2 || p.Name != "Updated from YAML" {
		t.Fatal(p, err)
	}
	w = yamlRequest("POST", "/api/v1/policies", []byte("id: duplicate\nid: other\n"))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	sim, err := os.ReadFile("../../examples/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	w = request(h, "POST", "/api/v1/policies/support-safety/simulate", string(sim))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestProviderStatusDoesNotExposeKey(t *testing.T) {
	app, h := testServer(t, "", true)
	app.Provider.Name = "requesty"
	app.Provider.Endpoint = "https://router.requesty.ai/v1/chat/completions"
	app.Provider.Format = "questions-chat"
	app.Provider.DefaultModel = "typesafe/jev-latest"
	app.Provider.APIKey = "private-config-secret"
	w := request(h, "GET", "/api/v1/status", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "requesty") || strings.Contains(w.Body.String(), "private-config-secret") {
		t.Fatal("provider status incorrect or sensitive")
	}
	w = request(h, "GET", "/playground", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "requesty") || strings.Contains(w.Body.String(), "private-config-secret") {
		t.Fatal("provider UI incorrect or sensitive")
	}
}
