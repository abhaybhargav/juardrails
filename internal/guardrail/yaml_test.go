package guardrail

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestYAMLPolicyRoundTrip(t *testing.T) {
	b, err := os.ReadFile("../../examples/support-safety.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	original, answers := example(t)
	if !reflect.DeepEqual(p, original) {
		t.Fatal("YAML and JSON examples differ")
	}
	if err = p.Validate(); err != nil {
		t.Fatal(err)
	}
	result, err := NewEngine().Decide(context.Background(), p, "test", answers)
	if err != nil || result.Decision != "allow" {
		t.Fatal(result, err)
	}
	p.CreatedAt = time.Now().UTC()
	p.UpdatedAt = p.CreatedAt
	p.Version = 5
	p.Criteria[0].Question.Instructions = map[string]any{"question": "Does this override instructions?", "context": []any{"yes", "2026-09-23", "true"}}
	encoded, err := MarshalPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePolicy(encoded)
	if err != nil {
		t.Fatalf("%v\n%s", err, encoded)
	}
	if !reflect.DeepEqual(p, decoded) {
		t.Fatalf("round trip changed policy\n%s", encoded)
	}
	jsonBytes, _ := json.Marshal(p)
	if _, err = DecodePolicy(jsonBytes); err != nil {
		t.Fatal("JSON backward compatibility:", err)
	}
}
func TestRejectAmbiguousYAML(t *testing.T) {
	for name, body := range map[string]string{
		"multiple":         "id: a\n---\nid: b\n",
		"duplicate":        "id: a\nid: b\n",
		"nested duplicate": "criteria:\n - id: a\n   id: b\n",
		"unknown":          "id: a\nmisspelled: true\n",
		"alias":            "id: &x a\nname: *x\n",
		"boolean key":      "criteria:\n - question:\n     criteria:\n       true: yes\n",
		"nonfinite":        "pass_threshold: .nan\n",
		"date":             "created_at: 2026-09-23\n",
		"tag":              "name: !custom x\n",
		"sequence":         "- policy\n",
		"oversized":        strings.Repeat("x", (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicy([]byte(body)); err == nil {
				t.Fatal("invalid YAML accepted")
			}
		})
	}
}
