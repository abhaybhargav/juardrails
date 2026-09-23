package config

import (
	"fmt"
	"net/url"
	"strings"
)

type Provider struct {
	Name         string `json:"name"`
	Endpoint     string `json:"endpoint"`
	Format       string `json:"format"`
	DefaultModel string `json:"default_model"`
	APIKey       string `json:"-"`
}

// ProviderFromEnv never falls back to another provider's credential.
func ProviderFromEnv(get func(string) string) (Provider, error) {
	p := Provider{Name: strings.ToLower(strings.TrimSpace(get("JEV_PROVIDER")))}
	if p.Name == "" {
		p.Name = "typesafe"
	}
	keyVar := ""
	switch p.Name {
	case "typesafe":
		p.Endpoint = "https://api.typesafe.ai/v1/systemone"
		p.Format = "systemone"
		p.DefaultModel = "jev-latest"
		keyVar = "TYPESAFE_API_KEY"
	case "openrouter":
		p.Endpoint = "https://openrouter.ai/api/v1/systemone"
		p.Format = "systemone"
		p.DefaultModel = "~typesafe/jev-latest"
		keyVar = "OPENROUTER_API_KEY"
	case "requesty":
		p.Endpoint = "https://router.requesty.ai/v1/chat/completions"
		p.Format = "questions-chat"
		p.DefaultModel = "typesafe/jev-latest"
		keyVar = "REQUESTY_API_KEY"
	case "custom":
	default:
		return p, fmt.Errorf("JEV_PROVIDER must be typesafe, openrouter, requesty or custom")
	}
	p.APIKey = get("JEV_API_KEY")
	if p.APIKey == "" && keyVar != "" {
		p.APIKey = get(keyVar)
	}
	if p.Name == "typesafe" && get("TYPESAFE_BASE_URL") != "" {
		p.Endpoint = strings.TrimRight(get("TYPESAFE_BASE_URL"), "/") + "/v1/systemone"
	}
	if v := get("JEV_ENDPOINT_URL"); v != "" {
		p.Endpoint = v
	}
	if v := get("JEV_API_FORMAT"); v != "" {
		p.Format = v
	}
	if v := get("JEV_DEFAULT_MODEL"); v != "" {
		p.DefaultModel = v
	}
	if p.Format != "systemone" && p.Format != "questions-chat" {
		return p, fmt.Errorf("set JEV_API_FORMAT to systemone or questions-chat")
	}
	if strings.TrimSpace(p.DefaultModel) == "" {
		return p, fmt.Errorf("custom providers require JEV_DEFAULT_MODEL")
	}
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.Path == "/" {
		return p, fmt.Errorf("JEV_ENDPOINT_URL must be a full HTTP(S) endpoint URL without credentials, query or fragment")
	}
	return p, nil
}
