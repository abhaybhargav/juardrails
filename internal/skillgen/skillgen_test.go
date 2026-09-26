package skillgen

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

func TestGeneratePolicySkillBundle(t *testing.T) {
	var requested bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		if r.Header.Get("Authorization") != "Bearer one-time-key" {
			t.Error("provider did not receive the selected key")
		}
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Model != "test-model" {
			t.Error("model not sent", err, body.Model)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"{\"description\":\"Evaluate support responses for instruction overrides and data exposure.\",\"use_when\":\"Use this policy before sending a support response to a customer.\"}"}}]}`))
	}))
	defer provider.Close()
	data, err := os.ReadFile("../../examples/support-safety.json")
	if err != nil {
		t.Fatal(err)
	}
	var p guardrail.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	p.Status, p.Namespace, p.Version = "active", "root", 3
	b := Builder{Endpoint: provider.URL + "/v1/chat/completions", Model: "test-model"}
	archive, name, err := b.Generate(context.Background(), p, "one-time-key", "")
	if err != nil || !requested || name != "juardrails-root-support-safety" {
		t.Fatal(err, requested, name)
	}
	if bytes.Contains(archive, []byte("one-time-key")) {
		t.Fatal("credential leaked into bundle")
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(z.File) != 2 {
		t.Fatal(err)
	}
	for _, file := range z.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		out.ReadFrom(r)
		r.Close()
		if strings.HasSuffix(file.Name, "SKILL.md") {
			body := out.String()
			for _, want := range []string{"name: " + name, "revision 3", "juardrails cli -namespace root evaluate support-safety", "decision` is exactly `allow", "~/.juardrails/credentials.json"} {
				if !strings.Contains(body, want) {
					t.Fatalf("skill missing %q", want)
				}
			}
		} else if !strings.HasSuffix(file.Name, "references/policy.yaml") {
			t.Fatal("unexpected bundle member", file.Name)
		}
	}
	p.Status = "draft"
	if _, _, err = b.Generate(context.Background(), p, "one-time-key", ""); err == nil {
		t.Fatal("draft policy generated an unusable skill")
	}
}

func TestGenerateDoesNotForwardProviderKeyOnRedirect(t *testing.T) {
	var forwarded bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Authorization") != ""
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	b := Builder{Endpoint: redirect.URL + "/v1/chat/completions"}
	_, _, err := b.Generate(context.Background(), guardrail.Policy{Status: "active"}, "one-time-key", "")
	if err == nil || forwarded {
		t.Fatal("provider redirect followed or unexpectedly succeeded", err, forwarded)
	}
}
