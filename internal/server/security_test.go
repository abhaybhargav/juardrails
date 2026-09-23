package server

import (
	"encoding/json"
	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func call(h http.Handler, method, path, body, token, ns string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if ns != "" {
		r.Header.Set("X-Juardrails-Namespace", ns)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestAuthorizationBoundariesAndAudit(t *testing.T) {
	app, h := testServer(t, "raw", false)
	auditPath := filepath.Join(t.TempDir(), "events.jsonl")
	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	app.Audit = log
	admin, err := app.Auth.Login("admin", "test-password-long", "test")
	if err != nil {
		t.Fatal(err)
	}
	if w := call(h, "POST", "/api/v1/admin/principals", `{"name":"worker","kind":"service","super_admin":true}`, admin.Secret, ""); w.Code != 400 {
		t.Fatal("accepted admin role", w.Code)
	}
	p, err := app.Auth.CreatePrincipal("worker", "service", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := app.Auth.IssueServiceToken(p.ID, "worker-token", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/policies", "/api/v1/admin/principals", "/api/v1/admin/tokens", "/access"} {
		if w := call(h, "GET", path, "", raw, ""); w.Code != 403 {
			t.Fatal("unbound principal access", path, w.Code)
		}
	}
	pol, err := app.Auth.SavePolicy(access.Policy{Name: "root-reader", Rules: []access.Rule{{Namespace: "root", Actions: []string{"policies:read", "evaluations:read"}}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.Auth.Bind(p.ID, []string{pol.Name}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	if w := call(h, "POST", "/api/v1/policies", string(body), admin.Secret, ""); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(h, "GET", "/api/v1/policies/support-safety/revisions", "", raw, ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		path := "/api/v1/policies"
		if method != "POST" {
			path += "/support-safety?version=1"
		}
		if w := call(h, method, path, string(body), raw, ""); w.Code != 403 {
			t.Fatal("write allowed", method, w.Code)
		}
	}
	if w := call(h, "POST", "/api/v1/policies/support-safety/evaluate", `{"state":"SECRET-INPUT"}`, raw, ""); w.Code != 403 {
		t.Fatal("live allowed", w.Code)
	}
	if err = app.Store.SaveNamespace(guardrail.Namespace{Name: "team"}, true); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "GET", "/api/v1/policies", "", raw, "team"); w.Code != 403 {
		t.Fatal("namespace escaped", w.Code)
	}
	var policy guardrail.Policy
	json.Unmarshal(body, &policy)
	policy.Namespace = "team"
	b, _ := json.Marshal(policy)
	if w := call(h, "POST", "/api/v1/policies", string(b), admin.Secret, "root"); w.Code != 422 {
		t.Fatal("namespace spoof", w.Code)
	}
	if w := call(h, "POST", "/api/v1/policies", string(b), admin.Secret, "team"); w.Code != 201 {
		t.Fatal("same ID in namespace", w.Code, w.Body.String())
	}
	app.Store.InNamespace("team").Record(guardrail.Evaluation{ID: "private-result", CreatedAt: time.Now()})
	if w := call(h, "GET", "/api/v1/evaluations/private-result", "", raw, "root"); w.Code != 404 {
		t.Fatal("cross namespace result", w.Code)
	}
	if w := call(h, "POST", "/api/v1/admin/tokens", `{"principal_id":"`+p.ID+`","name":"no-expiry"}`, admin.Secret, ""); w.Code != 422 {
		t.Fatal("expiry not required", w.Code)
	}
	if w := call(h, "GET", "/api/v1/namespaces", "", raw, ""); w.Code != 200 || strings.Contains(w.Body.String(), "team") {
		t.Fatal("namespace discovery leak", w.Code, w.Body.String())
	}
	// Every request produces a durable start and outcome; credentials and bodies stay out.
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{raw, admin.Secret, "SECRET-INPUT", "test-password-long"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("audit secret leak")
		}
	}
	events := map[string][]audit.Event{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e audit.Event
		if err = json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events[e.RequestID] = append(events[e.RequestID], e)
	}
	for id, es := range events {
		if id == "" || es[0].Phase != "request" || es[len(es)-1].Phase != "response" || es[len(es)-1].Status == 0 {
			t.Fatal("incomplete audit", id, es)
		}
	}
	if err = app.Auth.Bind(p.ID, nil); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "GET", "/api/v1/policies", "", raw, ""); w.Code != 403 {
		t.Fatal("revoked binding remains", w.Code)
	}
	if err = log.Close(); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "POST", "/api/v1/namespaces", `{"name":"must-not-exist"}`, admin.Secret, ""); w.Code != 503 {
		t.Fatal("audit failure allowed", w.Code)
	}
	if app.Store.NamespaceExists("must-not-exist") {
		t.Fatal("mutation before audit commit")
	}
}
func TestPasswordSessionAndCSRF(t *testing.T) {
	app, h := testServer(t, "raw", false)
	if w := call(h, "GET", "/", "", "", ""); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatal("no login redirect", w.Code)
	}
	if w := call(h, "GET", "/api/v1/policies", "", "", ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call(h, "POST", "/api/v1/auth/login", `{"username":"admin","password":"test-password-long"}`, "", "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	var response struct {
		Token string `json:"token"`
		CSRF  string `json:"csrf_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)
	req := func(path, body, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(cookies[0])
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w = req("/api/v1/namespaces", `{"name":"csrf-denied"}`, ""); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if w = req("/api/v1/namespaces", `{"name":"csrf-ok"}`, response.CSRF); w.Code != 200 {
		t.Fatal("valid CSRF denied", w.Code, w.Body.String())
	}
	if w = req("/api/v1/auth/password", `{"current_password":"test-password-long","new_password":"replacement-password"}`, response.CSRF); w.Code != 204 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err := app.Auth.Authenticate(response.Token); err == nil {
		t.Fatal("session survived password change")
	}
	p, err := app.Auth.CreatePrincipal("svc", "service", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, raw, err := app.Auth.IssueServiceToken(p.ID, "test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	r.AddCookie(&http.Cookie{Name: "juard_session", Value: raw})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("service token used as browser cookie", w.Code)
	}
}

func TestAccessPolicyYAMLAPI(t *testing.T) {
	_, h := testServer(t, "", false)
	body := "name: yaml-reader\ndescription: Team reader\nrules:\n  - namespace: team/**\n    actions: [policies:read]\n"
	r := httptest.NewRequest("POST", "/api/v1/admin/access-policies", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/yaml")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var p access.Policy
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.Version != 1 {
		t.Fatal(p, err)
	}
	if w = call(h, "GET", "/api/v1/admin/access-policies/yaml-reader", "", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = call(h, "GET", "/api/v1/admin/access-policies/yaml-reader/revisions", "", "", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
	r = httptest.NewRequest("PUT", "/api/v1/admin/access-policies/yaml-reader", strings.NewReader(body+"version: 1\nsuper_admin: true\n"))
	r.Header.Set("Content-Type", "application/yaml")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("unknown field accepted", w.Code)
	}
}
