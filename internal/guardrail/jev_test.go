package guardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestJevWireContractAndRetries(t *testing.T) {
	p, answers := example(t)
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/systemone" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("wrong provider request")
		}
		var req struct {
			Model     string              `json:"model"`
			State     any                 `json:"state"`
			Questions map[string]Question `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Model != "jev-latest" || len(req.Questions) != 3 || req.Questions["data_exposure"].Type != "score" {
			t.Errorf("bad request %+v", req)
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(429)
			return
		}
		json.NewEncoder(w).Encode(JevResponse{Model: "jev-test", Answers: answers, Usage: map[string]int{"input_tokens": 100}})
	}))
	defer ts.Close()
	j := &Jev{APIKey: "test-key", BaseURL: ts.URL, Client: ts.Client()}
	got, err := j.Evaluate(context.Background(), p, "state")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Answers) != 3 || calls.Load() != 2 {
		t.Fatal(got, calls.Load())
	}
}
func TestJevFailures(t *testing.T) {
	p, _ := example(t)
	if _, err := (&Jev{}).Evaluate(context.Background(), p, "state"); err == nil {
		t.Fatal("missing key allowed")
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"unauthorized", 401, "secret-provider-debug"}, {"invalid json", 200, "not json"}, {"missing model", 200, `{"answers":{}}`}, {"overloaded", 529, "busy"}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			_, err := (&Jev{APIKey: "key", BaseURL: srv.URL}).Evaluate(context.Background(), p, "state")
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.status == 401 && err.Error() == tc.body {
				t.Fatal("leaked provider body")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(time.Millisecond) }))
	defer srv.Close()
	if _, err := (&Jev{APIKey: "key", BaseURL: srv.URL}).Evaluate(ctx, p, "state"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestGatewayWireContracts(t *testing.T) {
	p, answers := example(t)
	for _, format := range []string{"systemone", "questions-chat"} {
		t.Run(format, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/custom/endpoint" || r.Header.Get("Authorization") != "Bearer gateway-key" {
					t.Error("incorrect URL or credential")
				}
				var req map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				var model string
				json.Unmarshal(req["model"], &model)
				if model != "provider/jev-latest" {
					t.Error("default model not resolved")
				}
				if format == "systemone" {
					if len(req["questions"]) == 0 || len(req["state"]) == 0 {
						t.Error("native payload missing")
					}
					json.NewEncoder(w).Encode(map[string]any{"model": "provider/actual-model", "answers": answers, "usage": map[string]any{"input_tokens": 12, "output_tokens": 5, "cost": 0.0000042, "details": map[string]any{"cached": false}}})
					return
				}
				if req["state"] != nil || req["questions"] != nil {
					t.Error("native fields leaked into chat payload")
				}
				var messages []struct{ Role, Content string }
				if err := json.Unmarshal(req["messages"], &messages); err != nil {
					t.Fatal(err)
				}
				if len(messages) != 1 || messages[0].Role != "user" || messages[0].Content != `{"message":"sample"}` {
					t.Error("structured state not preserved as JSON text")
				}
				var rf struct {
					Type      string
					Questions map[string]Question
				}
				json.Unmarshal(req["response_format"], &rf)
				if rf.Type != "questions" || len(rf.Questions) != 3 {
					t.Error("questions response format missing")
				}
				encoded, _ := json.Marshal(answers)
				json.NewEncoder(w).Encode(map[string]any{"model": "provider/actual-model", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(encoded)}}}, "usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 5, "cost": .001}})
			}))
			defer srv.Close()
			got, err := (&Jev{APIKey: "gateway-key", Endpoint: srv.URL + "/custom/endpoint", Format: format, DefaultModel: "provider/jev-latest"}).Evaluate(context.Background(), p, map[string]any{"message": "sample"})
			if err != nil {
				t.Fatal(err)
			}
			if got.Model != "provider/actual-model" || got.Usage["input_tokens"] != 12 || got.Usage["output_tokens"] != 5 {
				t.Fatal(got)
			}
			result, err := NewEngine().Decide(context.Background(), p, "state", got.Answers)
			if err != nil || result.Decision != "allow" {
				t.Fatal(result, err)
			}
		})
	}
}
func TestGatewayMalformedResponses(t *testing.T) {
	for _, body := range []string{
		`{"model":"jev","choices":[]}`,
		`{"model":"jev","choices":[{"finish_reason":"length","message":{"role":"assistant","content":"{}"}}]}`,
		`{"model":"jev","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"not json"}}]}`,
		`{"model":"jev","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"null"}}]}`,
		`{"model":"jev","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"{}","refusal":"refused"}}]}`,
		`{"model":"jev","error":{"message":"private provider diagnostic"}}`,
	} {
		if _, err := decodeJevResponse([]byte(body), "questions-chat"); err == nil {
			t.Fatal("malformed gateway response accepted")
		}
	}
}
func TestGatewayPinnedModelAndTextState(t *testing.T) {
	p, answers := example(t)
	p.Model = "provider/pinned"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model    string
			Messages []struct{ Content string }
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Model != "provider/pinned" || len(body.Messages) != 1 || body.Messages[0].Content != "plain text" {
			t.Error("pinned model or string state changed")
		}
		b, _ := json.Marshal(answers)
		json.NewEncoder(w).Encode(map[string]any{"model": body.Model, "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": string(b)}}}})
	}))
	defer ts.Close()
	if _, err := (&Jev{APIKey: "key", Endpoint: ts.URL, Format: "questions-chat", DefaultModel: "alias"}).Evaluate(context.Background(), p, "plain text"); err != nil {
		t.Fatal(err)
	}
}

func TestProviderRedirectDoesNotForwardCredentials(t *testing.T) {
	p, _ := example(t)
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	_, err := (&Jev{APIKey: "never-forward", Endpoint: redirect.URL, Format: "systemone"}).Evaluate(context.Background(), p, "state")
	if err == nil || reached.Load() {
		t.Fatal("redirect followed or accepted")
	}
}
