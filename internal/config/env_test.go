package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEnv(t *testing.T) {
	const key = "JUARDRAILS_TEST_DOTENV_VALUE"
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	path := envFile(t, "# Local configuration\nexport "+key+"=\"test-value=with-equals\"\n")
	if err := LoadEnv(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(key); got != "test-value=with-equals" {
		t.Fatal("quoted dotenv value was not loaded")
	}
}

func TestEnvironmentTakesPrecedence(t *testing.T) {
	for _, value := range []string{"existing-value", ""} {
		t.Run("existing_"+value, func(t *testing.T) {
			const key = "JUARDRAILS_TEST_DOTENV_VALUE"
			t.Setenv(key, value)
			if err := LoadEnv(envFile(t, key+"=from-file\n")); err != nil {
				t.Fatal(err)
			}
			if os.Getenv(key) != value {
				t.Fatal("existing environment variable was overwritten")
			}
		})
	}
}

func TestOptionalFileAndRedactedErrors(t *testing.T) {
	if err := LoadEnv(filepath.Join(t.TempDir(), "missing.env")); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"!invalid-secret-key=value\n", "KEY=\"unterminated-secret-value\n"} {
		err := LoadEnv(envFile(t, content))
		if err == nil {
			t.Fatal("invalid dotenv file accepted")
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("dotenv parser leaked file contents")
		}
	}
	if err := LoadEnv(t.TempDir()); err == nil {
		t.Fatal("unreadable dotenv file accepted")
	}
}
