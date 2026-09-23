package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/abhaybhargav/juardrails/internal/access"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
	"github.com/abhaybhargav/juardrails/internal/securefile"
)

type credentialFile struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func credentialPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".juardrails", "credentials.json"), nil
}
func loadCredential() (credentialFile, error) {
	var c credentialFile
	path, err := credentialPath()
	if err != nil {
		return c, err
	}
	dir := filepath.Dir(path)
	if err = securefile.Check(dir, true); err != nil {
		return c, fmt.Errorf("credential directory %s: %w", dir, err)
	}
	if err = securefile.Check(path, false); err != nil {
		return c, fmt.Errorf("inject a private service credential at %s: %w", path, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return c, err
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	loopback := host == "localhost" || ip != nil && ip.IsLoopback()
	if c.Token == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Host == "" || u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return c, fmt.Errorf("credential needs a token and an HTTPS URL (HTTP is allowed only on loopback)")
	}
	return c, nil
}
func (c client) requireService() error {
	b, err := c.request("GET", "/auth/me", nil)
	if err != nil {
		return fmt.Errorf("service credential verification: %w", err)
	}
	var me struct {
		Principal struct {
			Kind string `json:"kind"`
		} `json:"principal"`
		TokenKind string `json:"token_kind"`
	}
	if err = json.Unmarshal(b, &me); err != nil {
		return err
	}
	if me.Principal.Kind != "service" || me.TokenKind != "service" {
		return fmt.Errorf("CLI requires a service account token")
	}
	return nil
}
func explainPolicy(data []byte) error {
	var p guardrail.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	fmt.Printf("%s (%s, version %d)\n%s\nNamespace: %s  Status: %s  Mode: %s  Model: %s\nPass threshold: %.2f\n", p.Name, p.ID, p.Version, p.Description, p.Namespace, p.Status, p.Mode, p.Model, p.PassThreshold)
	for _, c := range p.Criteria {
		fmt.Printf("\n- %s (%s): %s, weight %.2f, pass when %s", c.Name, c.ID, c.Question.Type, c.Weight, c.Pass.Operator)
		if c.Pass.Threshold != nil {
			fmt.Printf(" %.2f", *c.Pass.Threshold)
		}
		if len(c.Pass.Choices) > 0 {
			fmt.Printf(" %s", strings.Join(c.Pass.Choices, ", "))
		}
		fmt.Println()
	}
	if p.Rego != "" {
		fmt.Println("Legacy Rego content is present; this policy cannot be evaluated until migrated.")
	}
	return nil
}
func (c client) admin(args []string, read func(string) ([]byte, error)) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: juard admin users|access|tokens|namespaces|auth-settings OP ...")
	}
	resource, op := args[0], args[1]
	rest := args[2:]
	one := func() (string, error) {
		if len(rest) != 1 {
			return "", fmt.Errorf("%s %s expects one argument", resource, op)
		}
		return rest[0], nil
	}
	body := func(i int) ([]byte, error) {
		if len(rest) <= i {
			return nil, fmt.Errorf("missing JSON/YAML file")
		}
		return read(rest[i])
	}
	call := func(method, path string, b []byte) ([]byte, error) { return c.request(method, path, b) }
	switch resource {
	case "users":
		base := "/admin/principals"
		switch op {
		case "list":
			return call("GET", base, nil)
		case "get":
			id, e := one()
			if e != nil {
				return nil, e
			}
			return call("GET", base+"/"+url.PathEscape(id), nil)
		case "create":
			b, e := body(0)
			if e != nil {
				return nil, e
			}
			return call("POST", base, b)
		case "update", "password", "bindings":
			if len(rest) != 2 {
				return nil, fmt.Errorf("usage: juard admin users %s ID FILE", op)
			}
			b, e := body(1)
			if e != nil {
				return nil, e
			}
			suffix := ""
			method := "PUT"
			if op == "password" {
				suffix = "/password"
				method = "POST"
			}
			if op == "bindings" {
				suffix = "/bindings"
			}
			return call(method, base+"/"+url.PathEscape(rest[0])+suffix, b)
		case "get-bindings":
			id, e := one()
			if e != nil {
				return nil, e
			}
			return call("GET", base+"/"+url.PathEscape(id)+"/bindings", nil)
		case "delete":
			id, e := one()
			if e != nil {
				return nil, e
			}
			return call("DELETE", base+"/"+url.PathEscape(id), nil)
		}
	case "access":
		base := "/admin/access-policies"
		switch op {
		case "list":
			return call("GET", base, nil)
		case "get", "revisions":
			name, e := one()
			if e != nil {
				return nil, e
			}
			path := base + "/" + url.PathEscape(name)
			if op == "revisions" {
				path += "/revisions"
			}
			return call("GET", path, nil)
		case "create", "update":
			if op == "create" && len(rest) != 1 || op == "update" && len(rest) != 2 {
				return nil, fmt.Errorf("usage: juard admin access %s FILE [NAME]", op)
			}
			b, e := body(0)
			if e != nil {
				return nil, e
			}
			var policy access.Policy
			if e = guardrail.DecodeDocument(b, &policy); e != nil {
				return nil, e
			}
			b, e = json.Marshal(policy)
			if e != nil {
				return nil, e
			}
			if op == "create" {
				return call("POST", base, b)
			}
			if len(rest) != 2 {
				return nil, fmt.Errorf("update requires NAME")
			}
			if policy.Name != rest[1] {
				return nil, fmt.Errorf("policy name must match NAME")
			}
			if policy.Version == 0 {
				current, e := call("GET", base+"/"+url.PathEscape(rest[1]), nil)
				if e != nil {
					return nil, e
				}
				var old access.Policy
				if e = json.Unmarshal(current, &old); e != nil {
					return nil, e
				}
				policy.Version = old.Version
				b, e = json.Marshal(policy)
				if e != nil {
					return nil, e
				}
			}
			return call("PUT", base+"/"+url.PathEscape(rest[1]), b)
		case "delete":
			name, e := one()
			if e != nil {
				return nil, e
			}
			path := base + "/" + url.PathEscape(name)
			current, e := call("GET", path, nil)
			if e != nil {
				return nil, e
			}
			var p struct {
				Version int `json:"version"`
			}
			if e = json.Unmarshal(current, &p); e != nil {
				return nil, e
			}
			return call("DELETE", fmt.Sprintf("%s?version=%d", path, p.Version), nil)
		}
	case "tokens":
		base := "/admin/tokens"
		switch op {
		case "list":
			return call("GET", base, nil)
		case "create":
			b, e := body(0)
			if e != nil {
				return nil, e
			}
			return call("POST", base, b)
		case "revoke":
			id, e := one()
			if e != nil {
				return nil, e
			}
			return call("DELETE", base+"/"+url.PathEscape(id), nil)
		}
	case "namespaces":
		base := "/namespaces"
		switch op {
		case "list":
			return call("GET", base, nil)
		case "create", "update":
			b, e := body(0)
			if e != nil {
				return nil, e
			}
			method := "POST"
			if op == "update" {
				method = "PUT"
			}
			return call(method, base, b)
		}
	case "auth-settings":
		base := "/admin/auth-settings"
		switch op {
		case "get":
			return call("GET", base, nil)
		case "set":
			b, e := body(0)
			if e != nil {
				return nil, e
			}
			return call("PUT", base, b)
		}
	}
	return nil, fmt.Errorf("unknown admin operation %q %q", resource, op)
}
