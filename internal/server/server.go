package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/config"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

//go:embed web
var assets embed.FS

type Server struct {
	Provider      config.Provider
	Store         *guardrail.Store
	Engine        *guardrail.Engine
	Jev           guardrail.Evaluator
	Auth          *access.Manager
	Audit         *audit.Logger
	SecureCookies bool
	Live          bool
	templates     *template.Template
	slots         chan struct{}
}

func New(store *guardrail.Store, jev guardrail.Evaluator, auditLog *audit.Logger, live bool) (*Server, error) {
	auth, err := access.New(store.DB())
	if err != nil {
		return nil, err
	}
	provider, _ := config.ProviderFromEnv(func(string) string { return "" })
	return &Server{Provider: provider, Store: store, Engine: guardrail.NewEngine(), Jev: jev, Auth: auth, Audit: auditLog, Live: live, templates: template.Must(template.ParseFS(assets, "web/templates/*.html")), slots: make(chan struct{}, 16)}, nil
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	s.securityRoutes(m)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { reply(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"live_configured": s.Live, "authentication": true, "version": "0.2.0", "provider": s.Provider})
	})
	m.HandleFunc("GET /api/v1/policies", s.list)
	m.HandleFunc("POST /api/v1/policies", s.create)
	m.HandleFunc("POST /api/v1/policies/validate", s.validate)
	m.HandleFunc("GET /api/v1/policies/{id}", s.get)
	m.HandleFunc("PUT /api/v1/policies/{id}", s.update)
	m.HandleFunc("DELETE /api/v1/policies/{id}", s.delete)
	m.HandleFunc("GET /api/v1/policies/{id}/revisions", s.revisions)
	m.HandleFunc("POST /api/v1/policies/{id}/evaluate", s.evaluate)
	m.HandleFunc("POST /api/v1/policies/{id}/simulate", s.simulate)
	m.HandleFunc("GET /api/v1/evaluations", s.history)
	m.HandleFunc("GET /api/v1/evaluations/{id}", s.evaluation)
	m.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		b, _ := assets.ReadFile("web/openapi.json")
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	})
	static, _ := fs.Sub(assets, "web/static")
	m.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	for _, path := range []string{"GET /{$}", "GET /policies/new", "GET /policies/{id}", "GET /playground", "GET /evaluations", "GET /docs", "GET /access", "GET /account"} {
		m.HandleFunc(path, s.page)
	}
	return s.middleware(m)
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, guardrail.ErrNotFound):
		fail(w, 404, "not found")
	case errors.Is(err, guardrail.ErrConflict):
		fail(w, 409, err.Error())
	default:
		slog.Error("storage error", "error", err)
		fail(w, 500, "storage operation failed")
	}
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "Content-Type must be application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "body must contain exactly one JSON value")
		return false
	}
	return true
}
func decodePolicy(w http.ResponseWriter, r *http.Request, p *guardrail.Policy) bool {
	media := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if media == "application/json" {
		return decode(w, r, p)
	}
	if media != "application/yaml" && media != "application/x-yaml" && media != "text/yaml" {
		fail(w, 415, "policy Content-Type must be application/yaml or application/json")
		return false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		fail(w, 400, "policy body exceeds limit or could not be read")
		return false
	}
	next, err := guardrail.DecodePolicy(b)
	if err != nil {
		fail(w, 400, err.Error())
		return false
	}
	*p = next
	return true
}
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	ps, err := s.scoped(r).List()
	if err != nil {
		storeError(w, err)
		return
	}
	reply(w, 200, map[string]any{"items": ps})
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	p, err := s.scoped(r).Get(r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/yaml") || r.URL.Query().Get("format") == "yaml" {
		b, err := guardrail.MarshalPolicy(p)
		if err != nil {
			storeError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		w.Header().Set("Content-Disposition", `attachment; filename="`+p.ID+`.yaml"`)
		w.Write(b)
		return
	}
	reply(w, 200, p)
}
func (s *Server) create(w http.ResponseWriter, r *http.Request) { s.save(w, r, true) }
func (s *Server) update(w http.ResponseWriter, r *http.Request) { s.save(w, r, false) }
func (s *Server) save(w http.ResponseWriter, r *http.Request, create bool) {
	var p guardrail.Policy
	if !decodePolicy(w, r, &p) {
		return
	}
	if !create && p.ID != r.PathValue("id") {
		fail(w, 400, "body id must match the URL")
		return
	}
	if p.Namespace != "" && p.Namespace != namespaceOf(r) {
		fail(w, 422, "policy namespace must match X-Juardrails-Namespace")
		return
	}
	if err := s.Engine.Validate(r.Context(), p); err != nil {
		fail(w, 422, err.Error())
		return
	}
	p, err := s.scoped(r).Save(p, create)
	if err != nil {
		storeError(w, err)
		return
	}
	status := 200
	if create {
		status = 201
		w.Header().Set("Location", "/api/v1/policies/"+p.ID)
	}
	auditTarget(r, p.ID, p.Version)
	reply(w, status, p)
}
func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var p guardrail.Policy
	if !decodePolicy(w, r, &p) {
		return
	}
	if p.Namespace != "" && p.Namespace != namespaceOf(r) {
		fail(w, 422, "policy namespace must match X-Juardrails-Namespace")
		return
	}
	if err := s.Engine.Validate(r.Context(), p); err != nil {
		fail(w, 422, err.Error())
		return
	}
	reply(w, 200, map[string]bool{"valid": true})
}
func (s *Server) delete(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(r.URL.Query().Get("version"))
	if err != nil || version < 1 {
		fail(w, 400, "version query parameter is required")
		return
	}
	if err = s.scoped(r).Delete(r.PathValue("id"), version); err != nil {
		storeError(w, err)
		return
	}
	auditTarget(r, r.PathValue("id"), version)
	w.WriteHeader(204)
}
func (s *Server) revisions(w http.ResponseWriter, r *http.Request) {
	ps, err := s.scoped(r).Revisions(r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	reply(w, 200, map[string]any{"items": ps})
}
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) { s.run(w, r, false) }
func (s *Server) simulate(w http.ResponseWriter, r *http.Request) { s.run(w, r, true) }
func (s *Server) run(w http.ResponseWriter, r *http.Request, simulation bool) {
	var req struct {
		State   json.RawMessage             `json:"state"`
		Answers map[string]guardrail.Answer `json:"answers,omitempty"`
	}
	if !decode(w, r, &req) {
		return
	}
	state, err := guardrail.ValidateState(req.State)
	if err != nil {
		fail(w, 422, err.Error())
		return
	}
	if !simulation && req.Answers != nil {
		fail(w, 422, "supplied answers are only accepted by /simulate")
		return
	}
	if simulation && len(req.Answers) == 0 {
		fail(w, 422, "simulation requires supplied answers")
		return
	}
	p, err := s.scoped(r).Get(r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	if !simulation && p.Status != "active" {
		fail(w, 409, "activate the policy before live evaluation; drafts can be simulated")
		return
	}
	if !simulation && !s.Live {
		fail(w, 503, "The selected provider API key is not configured; use simulation with supplied answers")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 429, "evaluation capacity reached; retry shortly")
		return
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	source := "simulation"
	model := "supplied-answers"
	var usage map[string]int
	if !simulation {
		source = "jev"
		response, upstreamErr := s.Jev.Evaluate(ctx, p, state)
		err = upstreamErr
		req.Answers = response.Answers
		model = response.Model
		usage = response.Usage
	}
	result := guardrail.Evaluation{PolicyID: p.ID, PolicyName: p.Name, PolicyVersion: p.Version, Decision: "error", Results: []guardrail.CriterionResult{}}
	if err == nil {
		result, err = s.Engine.Decide(ctx, p, state, req.Answers)
	}
	result.Namespace = namespaceOf(r)
	result.ID = newID()
	result.Source = source
	if !simulation {
		result.Provider = s.Provider.Name
	}
	result.Model = model
	result.Usage = usage
	result.CreatedAt = started.UTC()
	result.DurationMS = time.Since(started).Milliseconds()
	if err != nil {
		result.Decision = "error"
		result.Error = err.Error()
	}
	// Never store input state. A completed decision is only returned after its audit record commits.
	if recordErr := s.scoped(r).Record(result); recordErr != nil {
		storeError(w, recordErr)
		return
	}
	status := 200
	if err != nil {
		status = 502
		if simulation {
			status = 422
		}
	}
	auditTarget(r, result.ID, result.PolicyVersion)
	reply(w, status, result)
}
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 1000 {
			fail(w, 400, "limit must be between 1 and 1000")
			return
		}
	}
	es, err := s.scoped(r).Evaluations(r.URL.Query().Get("policy_id"), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	reply(w, 200, map[string]any{"items": es})
}
func (s *Server) evaluation(w http.ResponseWriter, r *http.Request) {
	e, err := s.scoped(r).Evaluation(r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	reply(w, 200, e)
}
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	view, title := "policies", "Policies"
	switch {
	case r.URL.Path == "/policies/new":
		view, title = "editor", "New policy"
	case strings.HasPrefix(r.URL.Path, "/policies/"):
		view, title = "editor", "Edit policy"
	case r.URL.Path == "/playground":
		view, title = "playground", "Playground"
	case r.URL.Path == "/evaluations":
		view, title = "evaluations", "Evaluations"
	case r.URL.Path == "/access":
		view, title = "access", "Access control"
	case r.URL.Path == "/account":
		view, title = "account", "Your account"
	case r.URL.Path == "/docs":
		view, title = "docs", "Developer API"
	}
	data := map[string]any{"View": view, "Title": title, "Live": s.Live, "PolicyID": r.PathValue("id"), "ProviderName": s.Provider.Name, "Admin": current(r).Principal.SuperAdmin, "Username": current(r).Principal.Name}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("render template", "error", fmt.Sprint(err))
	}
}
