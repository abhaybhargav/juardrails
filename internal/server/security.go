package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/audit"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

type contextKey int

const sessionKey contextKey = 0
const eventKey contextKey = 1

func current(r *http.Request) access.Session {
	s, _ := r.Context().Value(sessionKey).(access.Session)
	return s
}
func namespaceOf(r *http.Request) string {
	n := r.Header.Get("X-Juardrails-Namespace")
	if n == "" {
		return "root"
	}
	return n
}
func (s *Server) scoped(r *http.Request) *guardrail.Store { return s.Store.InNamespace(namespaceOf(r)) }

type responseBuffer struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (b *responseBuffer) Header() http.Header { return b.header }
func (b *responseBuffer) WriteHeader(n int) {
	if b.status == 0 {
		b.status = n
	}
}
func (b *responseBuffer) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(p)
}
func actionFor(r *http.Request) string {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v1/policies") {
		switch r.Method {
		case "GET", "HEAD":
			return "policies:read"
		case "PUT":
			return "policies:update"
		case "DELETE":
			return "policies:delete"
		case "POST":
			if strings.HasSuffix(path, "/skill") {
				return "policies:read"
			}
			if strings.HasSuffix(path, "/evaluate") {
				return "policies:evaluate"
			}
			if strings.HasSuffix(path, "/simulate") {
				return "policies:simulate"
			}
			return "policies:create"
		}
	}
	if strings.HasPrefix(path, "/api/v1/evaluations") {
		return "evaluations:read"
	}
	if strings.HasPrefix(path, "/api/v1/admin/") {
		return "admin:" + strings.TrimPrefix(path, "/api/v1/admin/")
	}
	return r.Method + " " + path
}
func (s *Server) middleware(next http.Handler) http.Handler {
	protected := http.NewCrossOriginProtection().Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		event := &audit.Event{RemoteIP: ip, RequestID: newID(), Phase: "request", Method: r.Method, Resource: r.URL.Path, Namespace: namespaceOf(r), Action: actionFor(r)}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Request-ID", event.RequestID)
		if s.Audit == nil || s.Audit.Write(*event) != nil {
			fail(w, 503, "audit log unavailable")
			return
		}
		b := &responseBuffer{header: make(http.Header)}
		defer func() {
			if recover() != nil {
				b = &responseBuffer{header: make(http.Header)}
				fail(b, 500, "internal server error")
			}
			if b.status == 0 {
				b.status = 200
			}
			event.Phase = "response"
			event.Status = b.status
			event.DurationMS = time.Since(started).Milliseconds()
			if s.Audit.Write(*event) != nil {
				fail(w, 503, "audit completion failed; check operation state before retrying")
				return
			}
			for k, v := range b.header {
				w.Header()[k] = v
			}
			w.WriteHeader(b.status)
			w.Write(b.body.Bytes())
		}()
		r = r.WithContext(context.WithValue(r.Context(), eventKey, event))
		public := (r.Method == "GET" || r.Method == "HEAD") && (r.URL.Path == "/healthz" || r.URL.Path == "/login" || strings.HasPrefix(r.URL.Path, "/static/")) || r.Method == "POST" && r.URL.Path == "/api/v1/auth/login"
		if public {
			protected.ServeHTTP(b, r)
			return
		}
		raw := ""
		cookieAuth := false
		if h := r.Header.Get("Authorization"); h != "" {
			if strings.HasPrefix(h, "Bearer ") {
				raw = strings.TrimPrefix(h, "Bearer ")
			}
		} else if c, err := r.Cookie("juard_session"); err == nil {
			raw = c.Value
			cookieAuth = true
		}
		session, err := s.Auth.Authenticate(raw)
		if err != nil || cookieAuth && session.Token.Kind != "session" {
			if err != nil && !errors.Is(err, access.ErrDenied) {
				fail(b, 503, "authentication unavailable")
				return
			}
			if !strings.HasPrefix(r.URL.Path, "/api/") && (r.Method == "GET" || r.Method == "HEAD") {
				http.Redirect(b, r, "/login", 303)
			} else {
				fail(b, 401, "authentication required")
			}
			return
		}
		event.ActorID = session.Principal.ID
		event.Actor = session.Principal.Name
		event.ActorKind = session.Principal.Kind
		event.TokenID = session.Token.ID
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
		if cookieAuth && r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(access.CSRF(raw))) != 1 {
				fail(b, 403, "CSRF token required")
				return
			}
		}
		ns := namespaceOf(r)
		if !guardrail.ValidNamespace(ns) {
			fail(b, 400, "invalid namespace")
			return
		}
		adminAPI := strings.HasPrefix(r.URL.Path, "/api/v1/admin/") || r.URL.Path == "/api/v1/namespaces" && r.Method != "GET" && r.Method != "HEAD"
		if adminAPI || r.URL.Path == "/access" {
			if !session.Principal.SuperAdmin && !(adminAPI && session.Token.Kind == "service" && s.Auth.AllowedAdmin(session.Principal)) {
				fail(b, 403, "super-admin required")
				return
			}
		}
		if strings.HasPrefix(event.Action, "policies:") || event.Action == "evaluations:read" {
			allowed := s.Auth.Allowed(session.Principal, ns, event.Action)
			if r.URL.Path == "/api/v1/policies/validate" && r.Method == "POST" {
				allowed = allowed || s.Auth.Allowed(session.Principal, ns, "policies:update")
			}
			if !allowed {
				fail(b, 403, "access policy does not permit this namespace action")
				return
			}
			if !s.Store.NamespaceExists(ns) {
				fail(b, 404, "namespace not found")
				return
			}
		}
		event.Phase = "authorized"
		if err := s.Audit.Write(*event); err != nil {
			fail(b, 503, "audit log unavailable")
			return
		}
		protected.ServeHTTP(b, r)
	})
}
func accessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrDenied):
		fail(w, 401, err.Error())
	case errors.Is(err, access.ErrRateLimited):
		w.Header().Set("Retry-After", "900")
		fail(w, 429, err.Error())
	case errors.Is(err, access.ErrNotFound) || errors.Is(err, guardrail.ErrNotFound):
		fail(w, 404, err.Error())
	case errors.Is(err, access.ErrConflict) || errors.Is(err, guardrail.ErrConflict):
		fail(w, 409, err.Error())
	default:
		fail(w, 422, "operation failed: "+err.Error())
	}
}
func (s *Server) cookie(w http.ResponseWriter, r *http.Request, raw string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if raw == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: "juard_session", Value: raw, Path: "/", HttpOnly: true, Secure: s.SecureCookies || r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: maxAge})
}
func (s *Server) securityRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		s.templates.ExecuteTemplate(w, "login", nil)
	})
	m.HandleFunc("POST /api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &req) {
			return
		}
		if len(req.Username) > 128 || len(req.Password) > 256 {
			fail(w, 401, "invalid credentials")
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		v, err := s.Auth.Login(req.Username, req.Password, ip)
		if err != nil {
			accessError(w, err)
			return
		}
		event := r.Context().Value(eventKey).(*audit.Event)
		event.ActorID = v.Principal.ID
		event.Actor = v.Principal.Name
		event.ActorKind = "human"
		event.TokenID = v.Token.ID
		s.cookie(w, r, v.Secret, v.Token.ExpiresAt)
		reply(w, 200, map[string]any{"principal": v.Principal, "token": v.Secret, "expires_at": v.Token.ExpiresAt, "csrf_token": access.CSRF(v.Secret)})
	})
	m.HandleFunc("GET /api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		v := current(r)
		reply(w, 200, map[string]any{"principal": v.Principal, "token_kind": v.Token.Kind, "expires_at": v.Token.ExpiresAt, "csrf_token": access.CSRF(v.Secret)})
	})
	m.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Auth.RevokeToken(current(r).Token.ID); err != nil {
			accessError(w, err)
			return
		}
		s.cookie(w, r, "", time.Unix(0, 0))
		w.WriteHeader(204)
	})
	m.HandleFunc("POST /api/v1/auth/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Current string `json:"current_password"`
			Next    string `json:"new_password"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.Auth.ChangePassword(current(r).Principal.ID, req.Current, req.Next, false); err != nil {
			accessError(w, err)
			return
		}
		s.cookie(w, r, "", time.Unix(0, 0))
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Store.Namespaces()
		if err != nil {
			storeError(w, err)
			return
		}
		out := []guardrail.Namespace{}
		permissions := map[string][]string{}
		for _, n := range items {
			grants := []string{}
			for _, a := range access.Actions {
				if s.Auth.Allowed(current(r).Principal, n.Name, a) {
					grants = append(grants, a)
				}
			}
			if len(grants) > 0 {
				out = append(out, n)
				permissions[n.Name] = grants
			}
		}
		reply(w, 200, map[string]any{"items": out, "actions": access.Actions, "permissions": permissions})
	})
	for _, method := range []string{"POST", "PUT"} {
		m.HandleFunc(method+" /api/v1/namespaces", func(w http.ResponseWriter, r *http.Request) {
			var n guardrail.Namespace
			if !decode(w, r, &n) {
				return
			}
			err := s.Store.SaveNamespace(n, r.Method == "POST")
			if err != nil {
				accessError(w, err)
				return
			}
			items, err := s.Store.Namespaces()
			if err != nil {
				storeError(w, err)
				return
			}
			for _, saved := range items {
				if saved.Name == n.Name {
					auditTarget(r, saved.Name, 0)
					reply(w, 200, saved)
					return
				}
			}
			fail(w, 500, "namespace readback failed")
		})
	}
	m.HandleFunc("GET /api/v1/admin/principals", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Auth.Principals()
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, map[string]any{"items": items})
	})
	m.HandleFunc("GET /api/v1/admin/principals/{id}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Auth.Principal(r.PathValue("id"))
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, p)
	})
	m.HandleFunc("POST /api/v1/admin/principals", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name        string `json:"name"`
			Kind        string `json:"kind"`
			Description string `json:"description"`
			Password    string `json:"password"`
		}
		if !decode(w, r, &req) {
			return
		}
		p, err := s.Auth.CreatePrincipal(req.Name, req.Kind, req.Description, req.Password)
		if err != nil {
			accessError(w, err)
			return
		}
		auditTarget(r, p.ID, 0)
		auditDetails(r, map[string]any{"name": p.Name, "kind": p.Kind})
		reply(w, 201, p)
	})
	m.HandleFunc("PUT /api/v1/admin/principals/{id}", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Description string `json:"description"`
			Disabled    bool   `json:"disabled"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.Auth.UpdatePrincipal(r.PathValue("id"), req.Description, req.Disabled); err != nil {
			accessError(w, err)
			return
		}
		auditDetails(r, map[string]any{"disabled": req.Disabled})
		w.WriteHeader(204)
	})
	m.HandleFunc("DELETE /api/v1/admin/principals/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Auth.DeletePrincipal(r.PathValue("id")); err != nil {
			accessError(w, err)
			return
		}
		auditTarget(r, r.PathValue("id"), 0)
		w.WriteHeader(204)
	})
	m.HandleFunc("POST /api/v1/admin/principals/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		if !decode(w, r, &req) {
			return
		}
		p, err := s.Auth.Principal(r.PathValue("id"))
		if err != nil {
			accessError(w, err)
			return
		}
		if p.SuperAdmin {
			fail(w, 403, "use your account page to change the super-admin password")
			return
		}
		if err = s.Auth.ChangePassword(p.ID, "", req.Password, true); err != nil {
			accessError(w, err)
			return
		}
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /api/v1/admin/principals/{id}/bindings", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Auth.Bindings(r.PathValue("id"))
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, map[string]any{"policies": v})
	})
	m.HandleFunc("PUT /api/v1/admin/principals/{id}/bindings", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Policies []string `json:"policies"`
		}
		if !decode(w, r, &req) {
			return
		}
		if err := s.Auth.Bind(r.PathValue("id"), req.Policies); err != nil {
			accessError(w, err)
			return
		}
		auditDetails(r, map[string]any{"policies": req.Policies})
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /api/v1/admin/access-policies", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Auth.Policies()
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, map[string]any{"items": items})
	})
	for _, route := range []string{"POST /api/v1/admin/access-policies", "PUT /api/v1/admin/access-policies/{name}"} {
		m.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			var p access.Policy
			if !decodeAccessPolicy(w, r, &p) {
				return
			}
			if r.Method == "PUT" && p.Name != r.PathValue("name") {
				fail(w, 400, "name must match URL")
				return
			}
			v, err := s.Auth.SavePolicy(p, r.Method == "POST")
			if err != nil {
				accessError(w, err)
				return
			}
			auditTarget(r, v.Name, v.Version)
			reply(w, 200, v)
		})
	}
	m.HandleFunc("GET /api/v1/admin/access-policies/{name}", func(w http.ResponseWriter, r *http.Request) {
		p, err := s.Auth.Policy(r.PathValue("name"))
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, p)
	})

	m.HandleFunc("DELETE /api/v1/admin/access-policies/{name}", func(w http.ResponseWriter, r *http.Request) {
		v, _ := strconv.Atoi(r.URL.Query().Get("version"))
		if err := s.Auth.DeletePolicy(r.PathValue("name"), v); err != nil {
			accessError(w, err)
			return
		}
		auditTarget(r, r.PathValue("name"), v)
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /api/v1/admin/access-policies/{name}/revisions", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Auth.PolicyRevisions(r.PathValue("name"))
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, map[string]any{"items": items})
	})
	m.HandleFunc("GET /api/v1/admin/tokens", func(w http.ResponseWriter, r *http.Request) {
		items, err := s.Auth.Tokens()
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, map[string]any{"items": items})
	})
	m.HandleFunc("POST /api/v1/admin/tokens", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PrincipalID string    `json:"principal_id"`
			Name        string    `json:"name"`
			ExpiresAt   time.Time `json:"expires_at"`
		}
		if !decode(w, r, &req) {
			return
		}
		t, raw, err := s.Auth.IssueServiceToken(req.PrincipalID, req.Name, req.ExpiresAt)
		if err != nil {
			accessError(w, err)
			return
		}
		auditTarget(r, t.ID, 0)
		auditDetails(r, map[string]any{"principal_id": t.PrincipalID, "name": t.Name, "expires_at": t.ExpiresAt})
		reply(w, 201, map[string]any{"token": raw, "metadata": t})
	})
	m.HandleFunc("DELETE /api/v1/admin/tokens/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Auth.RevokeToken(r.PathValue("id")); err != nil {
			accessError(w, err)
			return
		}
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /api/v1/admin/auth-settings", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Auth.Settings()
		if err != nil {
			accessError(w, err)
			return
		}
		reply(w, 200, v)
	})
	m.HandleFunc("PUT /api/v1/admin/auth-settings", func(w http.ResponseWriter, r *http.Request) {
		var v access.Settings
		if !decode(w, r, &v) {
			return
		}
		if err := s.Auth.SaveSettings(v); err != nil {
			accessError(w, err)
			return
		}
		auditDetails(r, map[string]any{"password": v.Password, "otp": v.OTP, "sso": v.SSO, "session_minutes": v.SessionMinutes})
		reply(w, 200, v)
	})
}

func decodeAccessPolicy(w http.ResponseWriter, r *http.Request, p *access.Policy) bool {
	media := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if media == "application/json" {
		return decode(w, r, p)
	}
	if media != "application/yaml" && media != "application/x-yaml" && media != "text/yaml" {
		fail(w, 415, "access policy requires application/json or application/yaml")
		return false
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		fail(w, 400, "body exceeds limit or could not be read")
		return false
	}
	if err = guardrail.DecodeDocument(b, p); err != nil {
		fail(w, 400, err.Error())
		return false
	}
	return true
}

func auditTarget(r *http.Request, target string, version int) {
	if e, ok := r.Context().Value(eventKey).(*audit.Event); ok {
		e.Target = target
		e.Version = version
	}
}

// Only explicitly selected, non-secret fields belong in audit metadata.
func auditDetails(r *http.Request, details map[string]any) {
	if e, ok := r.Context().Value(eventKey).(*audit.Event); ok {
		e.Details = details
	}
}
