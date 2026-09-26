package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/abhaybhargav/juardrails/internal/skillgen"
)

func (s *Server) skill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		APIKey string `json:"api_key"`
		Model  string `json:"model"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.APIKey) > 1024 {
		fail(w, 422, "AI provider API key is too long")
		return
	}
	p, err := s.scoped(r).Get(r.PathValue("id"))
	if err != nil {
		storeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	bundle, name, err := s.SkillAI.Generate(ctx, p, req.APIKey, req.Model)
	if err != nil {
		switch {
		case errors.Is(err, skillgen.ErrNotConfigured):
			fail(w, 409, err.Error())
		case p.Status != "active":
			fail(w, 409, err.Error())
		default:
			fail(w, 502, err.Error())
		}
		return
	}
	auditTarget(r, p.ID, p.Version)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	w.Header().Set("X-Juardrails-Skill-Name", name)
	w.Write(bundle)
}
