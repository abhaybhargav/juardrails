package guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type JevResponse struct {
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   map[string]int    `json:"usage"`
}
type Evaluator interface {
	Evaluate(context.Context, Policy, any) (JevResponse, error)
}
type Jev struct {
	APIKey       string
	Endpoint     string
	Format       string
	DefaultModel string
	BaseURL      string
	Client       *http.Client
}

func (j *Jev) Evaluate(ctx context.Context, p Policy, state any) (JevResponse, error) {
	var result JevResponse
	if j.APIKey == "" {
		return result, fmt.Errorf("live evaluation requires a configured provider API key; use simulation to test supplied answers")
	}
	questions := map[string]Question{}
	for _, c := range p.Criteria {
		questions[c.ID] = c.Question
	}
	format := j.Format
	if format == "" {
		format = "systemone"
	}
	if format != "systemone" && format != "questions-chat" {
		return result, fmt.Errorf("unsupported Jev API format")
	}
	model := p.Model
	if model == "jev-latest" && j.DefaultModel != "" {
		model = j.DefaultModel
	}
	payload := map[string]any{"model": model, "state": state, "questions": questions}
	if format == "questions-chat" {
		content, ok := state.(string)
		if !ok {
			encoded, err := json.Marshal(state)
			if err != nil {
				return result, err
			}
			content = string(encoded)
		}
		payload = map[string]any{"model": model, "stream": false, "messages": []map[string]string{{"role": "user", "content": content}}, "response_format": map[string]any{"type": "questions", "questions": questions}}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	endpoint := j.Endpoint
	if endpoint == "" {
		base := strings.TrimRight(j.BaseURL, "/")
		if base == "" {
			base = "https://api.typesafe.ai"
		}
		endpoint = base + "/v1/systemone"
	}
	client := j.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return result, err
		}
		req.Header.Set("Authorization", "Bearer "+j.APIKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return result, fmt.Errorf("Jev request failed; check provider connectivity or request timeout")
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
		resp.Body.Close()
		if readErr != nil {
			return result, fmt.Errorf("read Jev response: %w", readErr)
		}
		if len(data) > 4<<20 {
			return result, fmt.Errorf("Jev response exceeded 4 MiB")
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529 {
			if attempt == 2 {
				return result, fmt.Errorf("Jev is rate limited or overloaded (HTTP %d)", resp.StatusCode)
			}
			delay := time.Duration(1<<attempt) * 250 * time.Millisecond
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds >= 0 {
				delay = time.Duration(seconds) * time.Second
			} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
				delay = time.Until(at)
			}
			if delay > 5*time.Second {
				return result, fmt.Errorf("Jev requests a longer retry delay; try again later")
			}
			if delay < 0 {
				delay = 0
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return result, fmt.Errorf("Jev returned HTTP %d; check credentials, model and provider availability", resp.StatusCode)
		}
		result, err = decodeJevResponse(data, format)
		if err != nil {
			return result, err
		}

		return result, nil
	}
	return result, fmt.Errorf("Jev request failed")
}

// Decode only token-count fields from usage; gateways may include fractional
// costs and nested accounting metadata that are not token counts.
func decodeJevResponse(data []byte, format string) (JevResponse, error) {
	var wire struct {
		Model   string                     `json:"model"`
		Answers map[string]Answer          `json:"answers"`
		Error   json.RawMessage            `json:"error"`
		Usage   map[string]json.RawMessage `json:"usage"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Role    string  `json:"role"`
				Content *string `json:"content"`
				Refusal *string `json:"refusal"`
			} `json:"message"`
		} `json:"choices"`
	}
	var result JevResponse
	if err := json.Unmarshal(data, &wire); err != nil {
		return result, fmt.Errorf("invalid Jev response JSON")
	}
	if len(wire.Error) > 0 && string(wire.Error) != "null" {
		return result, fmt.Errorf("provider returned an error response")
	}
	if wire.Model == "" {
		return result, fmt.Errorf("Jev response is missing model")
	}
	result.Model = wire.Model
	result.Answers = wire.Answers
	if format == "questions-chat" {
		if len(wire.Choices) != 1 {
			return result, fmt.Errorf("provider must return exactly one answer message")
		}
		c := wire.Choices[0]
		if c.FinishReason != "stop" || c.Message.Role != "assistant" || c.Message.Content == nil || (c.Message.Refusal != nil && *c.Message.Refusal != "") {
			return result, fmt.Errorf("provider returned an incomplete or refused answer")
		}
		if err := json.Unmarshal([]byte(*c.Message.Content), &result.Answers); err != nil {
			return result, fmt.Errorf("provider answer content must be a JSON map of typed answers")
		}
	}
	if len(result.Answers) == 0 {
		return result, fmt.Errorf("Jev response is missing answers")
	}
	result.Usage = map[string]int{}
	for dst, keys := range map[string][]string{"input_tokens": {"input_tokens", "prompt_tokens"}, "output_tokens": {"output_tokens", "completion_tokens"}} {
		for _, key := range keys {
			if raw, ok := wire.Usage[key]; ok {
				var count int
				if err := json.Unmarshal(raw, &count); err != nil || count < 0 {
					return result, fmt.Errorf("provider returned invalid token usage")
				}
				result.Usage[dst] = count
				break
			}
		}
	}
	return result, nil
}
