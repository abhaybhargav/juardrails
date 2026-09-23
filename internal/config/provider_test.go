package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProviderPresets(t *testing.T) {
	for _, tc := range []struct{ name, key, path, format, model string }{
		{"typesafe", "TYPESAFE_API_KEY", "https://api.typesafe.ai/v1/systemone", "systemone", "jev-latest"},
		{"openrouter", "OPENROUTER_API_KEY", "https://openrouter.ai/api/v1/systemone", "systemone", "~typesafe/jev-latest"},
		{"requesty", "REQUESTY_API_KEY", "https://router.requesty.ai/v1/chat/completions", "questions-chat", "typesafe/jev-latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"JEV_PROVIDER": tc.name, tc.key: "secret-test-value", "TYPESAFE_BASE_URL": ""}
			p, err := ProviderFromEnv(func(k string) string { return env[k] })
			if err != nil {
				t.Fatal(err)
			}
			if p.Endpoint != tc.path || p.Format != tc.format || p.DefaultModel != tc.model || p.APIKey != "secret-test-value" {
				t.Fatal("incorrect provider resolution")
			}
			b, _ := json.Marshal(p)
			if strings.Contains(string(b), "secret-test-value") {
				t.Fatal("credential leaked")
			}
		})
	}
}
func TestProviderOverridesAndIsolation(t *testing.T) {
	env := map[string]string{"JEV_PROVIDER": "requesty", "TYPESAFE_API_KEY": "official-only", "TYPESAFE_BASE_URL": "https://official-only.invalid"}
	get := func(k string) string { return env[k] }
	p, err := ProviderFromEnv(get)
	if err != nil || p.APIKey != "" || p.Endpoint != "https://router.requesty.ai/v1/chat/completions" {
		t.Fatal("cross-provider credential/config fallback")
	}
	env["JEV_API_KEY"] = "generic"
	env["REQUESTY_API_KEY"] = "specific"
	env["JEV_ENDPOINT_URL"] = "http://127.0.0.1:1234/proxy/custom-path"
	env["JEV_DEFAULT_MODEL"] = "typesafe/pinned"
	p, err = ProviderFromEnv(get)
	if err != nil || p.APIKey != "generic" || p.Endpoint != env["JEV_ENDPOINT_URL"] || p.DefaultModel != "typesafe/pinned" {
		t.Fatal("override failed")
	}
	env["JEV_PROVIDER"] = "custom"
	env["JEV_API_FORMAT"] = "systemone"
	if _, err = ProviderFromEnv(get); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"/relative", "ftp://host/path", "https://user:password@host/path", "https://host/path?key=secret", "https://host/path#fragment", "https://host"} {
		env["JEV_ENDPOINT_URL"] = endpoint
		if _, err = ProviderFromEnv(get); err == nil {
			t.Fatal("accepted invalid endpoint")
		}
	}
}
func TestLegacyProviderDefaults(t *testing.T) {
	env := map[string]string{"TYPESAFE_API_KEY": "legacy", "TYPESAFE_BASE_URL": "http://localhost:1234/proxy/"}
	p, err := ProviderFromEnv(func(k string) string { return env[k] })
	if err != nil || p.Name != "typesafe" || p.Endpoint != "http://localhost:1234/proxy/v1/systemone" || p.APIKey != "legacy" {
		t.Fatal("legacy configuration changed")
	}
	for _, env := range []map[string]string{{"JEV_PROVIDER": "invalid"}, {"JEV_PROVIDER": "custom"}, {"JEV_API_FORMAT": "unknown"}} {
		if _, err := ProviderFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
