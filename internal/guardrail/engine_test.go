package guardrail

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func example(t *testing.T) (Policy, map[string]Answer) {
	t.Helper()
	b, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile("../../examples/simulation.json")
	if err != nil {
		t.Fatal(err)
	}
	var req struct {
		Answers map[string]Answer `json:"answers"`
	}
	if err = json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	return p, req.Answers
}
func TestDecisionModesAndBoundaries(t *testing.T) {
	cases := []struct {
		name, mode                  string
		noul, confidence, threshold float64
		want                        string
	}{
		{"all pass", "all", .2, .9, .8, "allow"}, {"exact threshold", "all", .2, .9, .8, "allow"}, {"above threshold", "all", .20001, .9, .8, "block"},
		{"any pass", "any", .9, .9, .8, "allow"}, {"weighted below", "weighted", .9, .9, .51, "block"}, {"weighted equal", "weighted", .9, .9, .5, "allow"},
		{"confidence gate", "all", .1, .49, .8, "review"}, {"confidence equal", "all", .1, .5, .8, "allow"}, {"review dominates allow", "any", .1, .1, .8, "review"}, {"review dominates block", "all", .9, .1, .8, "review"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, a := example(t)
			p.Mode = tc.mode
			p.PassThreshold = tc.threshold
			n := a["prompt_injection"]
			n.Noul = Number(tc.noul)
			a["prompt_injection"] = n
			c := a["intent"]
			c.Confidence = Number(tc.confidence)
			a["intent"] = c
			e, err := NewEngine().Decide(context.Background(), p, "state", a)
			if err != nil {
				t.Fatal(err)
			}
			if e.Decision != tc.want {
				t.Fatalf("got %s want %s", e.Decision, tc.want)
			}
		})
	}
}
func TestOperators(t *testing.T) {
	for _, tc := range []struct {
		op    string
		value float64
		want  bool
	}{{"lt", .2, false}, {"lt", .19, true}, {"lte", .2, true}, {"gt", .2, false}, {"gt", .21, true}, {"gte", .2, true}} {
		t.Run(tc.op, func(t *testing.T) {
			p, a := example(t)
			p.Criteria = p.Criteria[:1]
			p.Criteria[0].Pass.Operator = tc.op
			n := a["prompt_injection"]
			n.Noul = Number(tc.value)
			a["prompt_injection"] = n
			e, err := NewEngine().Decide(context.Background(), p, "state", a)
			if err != nil {
				t.Fatal(err)
			}
			if (e.Decision == "allow") != tc.want {
				t.Fatal(e)
			}
		})
	}
	p, a := example(t)
	p.Criteria = p.Criteria[1:2]
	p.Criteria[0].Pass.Operator = "not_in"
	e, err := NewEngine().Decide(context.Background(), p, "state", a)
	if err != nil || e.Decision != "block" {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestMalformedAnswersFail(t *testing.T) {
	tests := map[string]func(map[string]Answer){
		"missing":              func(a map[string]Answer) { delete(a, "intent") },
		"wrong type":           func(a map[string]Answer) { x := a["intent"]; x.Type = "noul"; a["intent"] = x },
		"missing confidence":   func(a map[string]Answer) { x := a["intent"]; x.Confidence = nil; a["intent"] = x },
		"unknown choice":       func(a map[string]Answer) { x := a["intent"]; x.Choice = "invented"; a["intent"] = x },
		"missing score":        func(a map[string]Answer) { x := a["data_exposure"]; x.Score = nil; a["data_exposure"] = x },
		"out of range":         func(a map[string]Answer) { x := a["prompt_injection"]; x.Noul = Number(1.1); a["prompt_injection"] = x },
		"missing distribution": func(a map[string]Answer) { x := a["intent"]; x.Probabilities = nil; a["intent"] = x },
		"wrong total":          func(a map[string]Answer) { a["intent"].Probabilities["support"] = .1 },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, a := example(t)
			change(a)
			if _, err := NewEngine().Decide(context.Background(), p, "state", a); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}
func TestPolicyValidation(t *testing.T) {
	tests := map[string]func(*Policy){"duplicate IDs": func(p *Policy) { p.Criteria[1].ID = p.Criteria[0].ID }, "empty": func(p *Policy) { p.Criteria = nil }, "bad weight": func(p *Policy) { p.Criteria[0].Weight = 0 }, "score threshold": func(p *Policy) { p.Criteria[2].Pass.Threshold = Number(4) }, "noul confidence": func(p *Policy) { p.Criteria[0].Pass.MinConfidence = .5 }, "unknown option": func(p *Policy) { p.Criteria[1].Pass.Choices = []string{"oops"} }, "bad instructions": func(p *Policy) { p.Criteria[0].Question.Instructions = 2 }}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, _ := example(t)
			change(&p)
			if p.Validate() == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	p, _ := example(t)
	p.Criteria[0].Question.Instructions = map[string]any{"question": "Is this safe?", "context": []any{"a", "b"}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyRegoFailsClosed(t *testing.T) {
	p, a := example(t)
	p.Mode = "rego"
	p.Rego = "package guardrails\ndefault decision := \"allow\""
	if _, err := NewEngine().Decide(context.Background(), p, "state", a); err == nil {
		t.Fatal("legacy Rego must not silently change meaning")
	}
	p.Mode = "all"
	if err := p.Validate(); err == nil {
		t.Fatal("legacy code must be removed explicitly")
	}
}
func TestStoreRevisionPersistenceAndConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := example(t)
	p, err = s.Save(p, true)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 {
		t.Fatal(p.Version)
	}
	if _, err = s.Save(p, true); err != ErrConflict {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	success := make(chan Policy, 2)
	failures := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next, err := s.Save(p, false)
			if err != nil {
				failures <- err
			} else {
				success <- next
			}
		}()
	}
	wg.Wait()
	if len(success) != 1 || len(failures) != 1 {
		t.Fatal("concurrency was not enforced")
	}
	if err = <-failures; err != ErrConflict {
		t.Fatal(err)
	}
	updated := <-success
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(p.ID)
	if err != nil || got.Version != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	rs, err := s.Revisions(p.ID)
	if err != nil || len(rs) != 2 {
		t.Fatal(rs, err)
	}
	if err = s.Delete(p.ID, 1); err != ErrConflict {
		t.Fatal(err)
	}
	if err = s.Delete(p.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(p, true); err == nil {
		t.Fatal("reused historical id")
	}
	if _, err = s.Get(p.ID); err != ErrNotFound {
		t.Fatal("failed transaction must not create policy")
	}
	rs, err = s.Revisions(p.ID)
	if err != nil || len(rs) != 2 {
		t.Fatal("delete removed history")
	}
}
