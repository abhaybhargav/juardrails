package guardrail

import (
	"context"
	"os"
	"testing"
)

func TestClaudeCodePackPolicy(t *testing.T) {
	data, err := os.ReadFile("../../policy_packs/claude-code/policies/claude-code-tool-use.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.ID != "claude-code-tool-use" || p.Status != "active" {
		t.Fatal("pack policy must be active")
	}
	answers := map[string]Answer{}
	low := 0.01
	high := 0.95
	for _, c := range p.Criteria {
		answers[c.ID] = Answer{Type: "noul", Noul: &low}
	}
	result, err := NewEngine().Decide(context.Background(), p, nil, answers)
	if err != nil || result.Decision != "allow" {
		t.Fatalf("safe call: %+v %v", result, err)
	}
	for _, c := range p.Criteria {
		answers[c.ID] = Answer{Type: "noul", Noul: &high}
		result, err = NewEngine().Decide(context.Background(), p, nil, answers)
		if err != nil || result.Decision != "block" {
			t.Fatalf("risk %s: %+v %v", c.ID, result, err)
		}
		answers[c.ID] = Answer{Type: "noul", Noul: &low}
	}
	moderate := 0.35
	answers["secret_exposure"] = Answer{Type: "noul", Noul: &moderate}
	result, err = NewEngine().Decide(context.Background(), p, nil, answers)
	if err != nil || result.Decision != "allow" {
		t.Fatalf("ordinary listing tolerance: %+v %v", result, err)
	}
}
