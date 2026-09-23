package guardrail

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

type Question struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}
type Condition struct {
	Operator      string   `json:"operator"`
	Threshold     *float64 `json:"threshold,omitempty"`
	Choices       []string `json:"choices,omitempty"`
	MinConfidence float64  `json:"min_confidence,omitempty"`
}
type Criterion struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Question Question  `json:"question"`
	Pass     Condition `json:"pass"`
	Weight   float64   `json:"weight"`
}
type Policy struct {
	Namespace     string      `json:"namespace,omitempty"`
	ID            string      `json:"id"`
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	Status        string      `json:"status"`
	Model         string      `json:"model"`
	Mode          string      `json:"mode"`
	PassThreshold float64     `json:"pass_threshold"`
	Criteria      []Criterion `json:"criteria"`
	Rego          string      `json:"rego,omitempty"`
	Version       int         `json:"version"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}
type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice,omitempty"`
	Score         *float64           `json:"score,omitempty"`
	Noul          *float64           `json:"noul,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Legend        map[string]any     `json:"legend,omitempty"`
}
type CriterionResult struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Passed    bool    `json:"passed"`
	Uncertain bool    `json:"uncertain"`
	Reason    string  `json:"reason"`
	Weight    float64 `json:"weight"`
	Answer    Answer  `json:"answer"`
}
type Evaluation struct {
	Namespace     string            `json:"namespace,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	ID            string            `json:"id"`
	PolicyID      string            `json:"policy_id"`
	PolicyName    string            `json:"policy_name"`
	PolicyVersion int               `json:"policy_version"`
	Decision      string            `json:"decision"`
	Score         float64           `json:"score"`
	Source        string            `json:"source"`
	Model         string            `json:"model"`
	Results       []CriterionResult `json:"results"`
	Usage         map[string]int    `json:"usage,omitempty"`
	Error         string            `json:"error,omitempty"`
	DurationMS    int64             `json:"duration_ms"`
	CreatedAt     time.Time         `json:"created_at"`
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func Number(v float64) *float64 { return &v }
func finite(v float64) bool     { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func description(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) != ""
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	}
	return false
}
func (p Policy) Validate() error {
	if p.Namespace != "" && !ValidNamespace(p.Namespace) {
		return fmt.Errorf("invalid namespace")
	}
	if !identifier.MatchString(p.ID) {
		return fmt.Errorf("id must start with a lowercase letter and contain 1–64 lowercase letters, digits, hyphens or underscores")
	}
	if strings.TrimSpace(p.Name) == "" || len(p.Name) > 160 {
		return fmt.Errorf("name is required (maximum 160 characters)")
	}
	if p.Status != "draft" && p.Status != "active" {
		return fmt.Errorf("status must be draft or active")
	}
	if strings.TrimSpace(p.Model) == "" {
		return fmt.Errorf("model is required")
	}
	if p.Mode != "all" && p.Mode != "any" && p.Mode != "weighted" {
		return fmt.Errorf("mode must be all, any or weighted; legacy Rego policies must be migrated explicitly")
	}
	if !finite(p.PassThreshold) || p.PassThreshold < 0 || p.PassThreshold > 1 {
		return fmt.Errorf("pass_threshold must be between 0 and 1")
	}
	if len(p.Criteria) == 0 || len(p.Criteria) > 100 {
		return fmt.Errorf("a policy needs 1–100 criteria")
	}
	if strings.TrimSpace(p.Rego) != "" {
		return fmt.Errorf("Rego is no longer supported; remove rego and choose all, any or weighted decision logic")
	}

	seen := map[string]bool{}
	for _, c := range p.Criteria {
		err := c.validate()
		if err != nil {
			return fmt.Errorf("criterion %q: %w", c.ID, err)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate criterion id %q", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}
func (c Criterion) validate() error {
	if !identifier.MatchString(c.ID) {
		return fmt.Errorf("invalid id")
	}
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if !description(c.Question.Instructions) {
		return fmt.Errorf("instructions must be a nonempty string, object or array")
	}
	if !finite(c.Weight) || c.Weight <= 0 || c.Weight > 1000 {
		return fmt.Errorf("weight must be greater than 0 and at most 1000")
	}
	if !finite(c.Pass.MinConfidence) || c.Pass.MinConfidence < 0 || c.Pass.MinConfidence > 1 {
		return fmt.Errorf("min_confidence must be between 0 and 1")
	}
	max := 1.0
	switch c.Question.Type {
	case "choice":
		opts, ok := c.Question.Criteria.(map[string]any)
		if !ok || len(opts) < 2 || len(opts) > 255 {
			return fmt.Errorf("choice needs 2–255 named options")
		}
		for k, v := range opts {
			if strings.TrimSpace(k) == "" || (v != nil && !description(v)) {
				return fmt.Errorf("invalid choice option %q", k)
			}
		}
		if c.Pass.Operator != "in" && c.Pass.Operator != "not_in" {
			return fmt.Errorf("choice operator must be in or not_in")
		}
		if len(c.Pass.Choices) == 0 {
			return fmt.Errorf("select at least one passing choice")
		}
		for _, k := range c.Pass.Choices {
			if _, ok := opts[k]; !ok {
				return fmt.Errorf("unknown passing choice %q", k)
			}
		}
		return nil
	case "score":
		levels, ok := c.Question.Criteria.([]any)
		if !ok || len(levels) < 2 || len(levels) > 10 {
			return fmt.Errorf("score needs 2–10 ordered levels")
		}
		for _, v := range levels {
			if !description(v) {
				return fmt.Errorf("each score level needs a description")
			}
		}
		max = float64(len(levels) - 1)
	case "noul":
		if c.Pass.MinConfidence != 0 {
			return fmt.Errorf("Noul has no confidence; use its probability threshold")
		}
		if c.Question.Criteria != nil {
			opts, ok := c.Question.Criteria.(map[string]any)
			if !ok {
				return fmt.Errorf("noul criteria must be an object")
			}
			for k, v := range opts {
				if (k != "true" && k != "false") || !description(v) {
					return fmt.Errorf("noul criteria supports only true and false descriptions")
				}
			}
		}
	default:
		return fmt.Errorf("type must be choice, score or noul")
	}
	switch c.Pass.Operator {
	case "gte", "gt", "lte", "lt":
	default:
		return fmt.Errorf("numeric operator must be gte, gt, lte or lt")
	}
	if c.Pass.Threshold == nil || !finite(*c.Pass.Threshold) || *c.Pass.Threshold < 0 || *c.Pass.Threshold > max {
		return fmt.Errorf("threshold must be between 0 and %g", max)
	}
	return nil
}
func ValidateState(raw json.RawMessage) (any, error) {
	var state any
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("state must be valid JSON")
	}
	if !description(state) {
		return nil, fmt.Errorf("state must be a nonempty string, object or array")
	}
	return state, nil
}
