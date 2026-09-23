package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/abhaybhargav/juardrails/internal/guardrail"
)

type client struct {
	base, token, namespace string
	http                   *http.Client
}
type apiError struct {
	status int
	body   []byte
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }
func (c client) request(method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+"/api/v1"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Juardrails-Namespace", c.namespace)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, &apiError{resp.StatusCode, data}
	}
	return data, nil
}

// Run executes service-account CLI commands from either juard or juardrails cli.
func Run(argv []string) error {
	ns := os.Getenv("JUARDRAILS_NAMESPACE")
	if ns == "" {
		ns = "root"
	}
	flags := flag.NewFlagSet("cli", flag.ContinueOnError)
	namespace := flags.String("namespace", ns, "policy namespace")
	if err := flags.Parse(argv); err != nil {
		return err
	}
	args := flags.Args()
	if len(args) == 0 {
		return fmt.Errorf("usage: juardrails cli [-namespace NAME] list | get ID | explain ID | apply FILE | validate FILE | delete ID | evaluate ID FILE | simulate ID FILE | history [ID] | revisions ID | admin ...\nCredential: ~/.juardrails/credentials.json (service token only). Use - for stdin")
	}
	credential, err := loadCredential()
	if err != nil {
		return err
	}
	c := client{strings.TrimRight(credential.URL, "/"), credential.Token, *namespace, &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if err := c.requireService(); err != nil {
		return err
	}
	var data []byte
	read := func(path string) ([]byte, error) {
		if path == "-" {
			return io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
		}
		return os.ReadFile(path)
	}
	need := func(n int) error {
		if len(args) != n {
			return fmt.Errorf("%s expects %d argument(s)", args[0], n-1)
		}
		return nil
	}
	switch args[0] {
	case "request":
		if len(args) < 3 || len(args) > 4 {
			return fmt.Errorf("usage: juard request METHOD /path [JSON_FILE|-]; path is relative to /api/v1")
		}
		if !strings.HasPrefix(args[2], "/") {
			return fmt.Errorf("path must start with /")
		}
		var body []byte
		if len(args) == 4 {
			body, err = read(args[3])
			if err != nil {
				return err
			}
		}
		data, err = c.request(strings.ToUpper(args[1]), args[2], body)
	case "admin":
		data, err = c.admin(args[1:], read)
	case "list":
		if err = need(1); err != nil {
			return err
		}
		data, err = c.request("GET", "/policies", nil)
	case "get", "export", "explain", "revisions", "delete":
		if err = need(2); err != nil {
			return err
		}
		path := "/policies/" + url.PathEscape(args[1])
		method := "GET"
		if args[0] == "revisions" {
			path += "/revisions"
		}
		if args[0] == "delete" {
			current, e := c.request("GET", path, nil)
			if e != nil {
				return e
			}
			var p struct {
				Version int `json:"version"`
			}
			if e = json.Unmarshal(current, &p); e != nil {
				return e
			}
			path += fmt.Sprintf("?version=%d", p.Version)
			method = "DELETE"
		}
		data, err = c.request(method, path, nil)
	case "apply", "validate":
		if err = need(2); err != nil {
			return err
		}
		body, e := read(args[1])
		if e != nil {
			return e
		}
		policy, decodeErr := guardrail.DecodePolicy(body)
		if decodeErr != nil {
			return decodeErr
		}
		body, e = json.Marshal(policy)
		if e != nil {
			return e
		}
		var p map[string]any
		if e = json.Unmarshal(body, &p); e != nil {
			return e
		}
		if args[0] == "validate" {
			data, err = c.request("POST", "/policies/validate", body)
			break
		}
		id, ok := p["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("policy id is required")
		}
		path := "/policies/" + url.PathEscape(id)
		current, e := c.request("GET", path, nil)
		if e != nil {
			var ae *apiError
			if errors.As(e, &ae) && ae.status == 404 {
				data, err = c.request("POST", "/policies", body)
			} else {
				return e
			}
		} else {
			var old map[string]any
			if e = json.Unmarshal(current, &old); e != nil {
				return e
			}
			if v, exists := p["version"]; !exists || v == float64(0) {
				p["version"] = old["version"]
			}
			body, e = json.Marshal(p)
			if e != nil {
				return e
			}
			data, err = c.request("PUT", path, body)
		}
	case "evaluate", "simulate":
		if err = need(3); err != nil {
			return err
		}
		body, e := read(args[2])
		if e != nil {
			return e
		}
		data, err = c.request("POST", "/policies/"+url.PathEscape(args[1])+"/"+args[0], body)
	case "history":
		if len(args) > 2 {
			return fmt.Errorf("history takes at most one policy ID")
		}
		path := "/evaluations"
		if len(args) == 2 {
			path += "?policy_id=" + url.QueryEscape(args[1])
		}
		data, err = c.request("GET", path, nil)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		return err
	}
	if args[0] == "explain" {
		return explainPolicy(data)
	}
	if args[0] == "get" || args[0] == "export" {
		var p guardrail.Policy
		if err = json.Unmarshal(data, &p); err != nil {
			return err
		}
		encoded, err := guardrail.MarshalPolicy(p)
		if err != nil {
			return err
		}
		fmt.Print(string(encoded))
		return nil
	}
	if len(data) == 0 {
		fmt.Println("Success.")
		return nil
	}
	var out bytes.Buffer
	if err = json.Indent(&out, data, "", "  "); err != nil {
		return err
	}
	fmt.Println(out.String())
	return nil
}
