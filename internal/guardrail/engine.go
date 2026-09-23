package guardrail

import (
	"context"

	"fmt"
	"math"
	"strconv"
)

type Engine struct{}

func NewEngine() *Engine                                       { return &Engine{} }
func (e *Engine) Validate(ctx context.Context, p Policy) error { return p.Validate() }
func validateAnswer(c Criterion, a Answer) error {
	if a.Type != c.Question.Type {
		return fmt.Errorf("answer type mismatch for %s", c.ID)
	}
	if a.Type == "noul" {
		if a.Noul == nil || !finite(*a.Noul) || *a.Noul < 0 || *a.Noul > 1 {
			return fmt.Errorf("%s: missing or invalid noul", c.ID)
		}
		return nil
	}
	if a.Confidence == nil || !finite(*a.Confidence) || *a.Confidence < 0 || *a.Confidence > 1 {
		return fmt.Errorf("%s: missing or invalid confidence", c.ID)
	}
	var keys []string
	if a.Type == "choice" {
		opts := c.Question.Criteria.(map[string]any)
		if _, ok := opts[a.Choice]; !ok {
			return fmt.Errorf("%s: unknown choice", c.ID)
		}
		for k := range opts {
			keys = append(keys, k)
		}
	} else {
		levels := c.Question.Criteria.([]any)
		if a.Score == nil || !finite(*a.Score) || *a.Score < 0 || *a.Score > float64(len(levels)-1) {
			return fmt.Errorf("%s: missing or out-of-range score", c.ID)
		}
		for i := range levels {
			keys = append(keys, strconv.Itoa(i))
		}
	}
	if len(a.Probabilities) != len(keys) {
		return fmt.Errorf("%s: probability distribution must cover every option or level", c.ID)
	}
	total := 0.0
	for _, k := range keys {
		v, ok := a.Probabilities[k]
		if !ok || !finite(v) || v < 0 || v > 1 {
			return fmt.Errorf("%s: invalid probability distribution", c.ID)
		}
		total += v
	}
	if math.Abs(total-1) > 0.02 {
		return fmt.Errorf("%s: probabilities must sum to 1", c.ID)
	}
	return nil
}
func (e *Engine) Decide(ctx context.Context, p Policy, state any, answers map[string]Answer) (Evaluation, error) {
	result := Evaluation{PolicyID: p.ID, PolicyName: p.Name, PolicyVersion: p.Version, Decision: "error", Results: []CriterionResult{}}
	if err := e.Validate(ctx, p); err != nil {
		return result, err
	}
	total, passed := 0.0, 0.0
	count := 0
	uncertain := false
	for _, c := range p.Criteria {
		a, ok := answers[c.ID]
		if !ok {
			return result, fmt.Errorf("missing answer for %s", c.ID)
		}
		if err := validateAnswer(c, a); err != nil {
			return result, err
		}
		r := CriterionResult{ID: c.ID, Name: c.Name, Answer: a, Weight: c.Weight}
		if a.Type == "choice" {
			for _, v := range c.Pass.Choices {
				if a.Choice == v {
					r.Passed = true
				}
			}
			if c.Pass.Operator == "not_in" {
				r.Passed = !r.Passed
			}
			r.Reason = fmt.Sprintf("choice %q %s %v", a.Choice, c.Pass.Operator, c.Pass.Choices)
		} else {
			value := a.Noul
			if a.Type == "score" {
				value = a.Score
			}
			threshold := *c.Pass.Threshold
			switch c.Pass.Operator {
			case "gte":
				r.Passed = *value >= threshold
			case "gt":
				r.Passed = *value > threshold
			case "lte":
				r.Passed = *value <= threshold
			case "lt":
				r.Passed = *value < threshold
			}
			r.Reason = fmt.Sprintf("%g %s %g", *value, c.Pass.Operator, threshold)
		}
		if a.Type != "noul" && *a.Confidence < c.Pass.MinConfidence {
			r.Uncertain = true
			r.Passed = false
			r.Reason = fmt.Sprintf("confidence %g is below %g", *a.Confidence, c.Pass.MinConfidence)
			uncertain = true
		}
		total += c.Weight
		if r.Passed {
			passed += c.Weight
			count++
		}
		result.Results = append(result.Results, r)
	}
	result.Score = passed / total
	allow := false
	switch p.Mode {
	case "all":
		allow = count == len(p.Criteria)
	case "any":
		allow = count > 0
	case "weighted":
		allow = result.Score >= p.PassThreshold
	}
	result.Decision = "block"
	if allow {
		result.Decision = "allow"
	}
	if uncertain {
		result.Decision = "review"
	}

	return result, nil
}
