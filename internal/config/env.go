package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

// LoadEnv reads an optional dotenv file without replacing existing environment
// variables. Parser diagnostics are deliberately omitted because they can contain
// credential-bearing lines from the file.
func LoadEnv(path string) error {
	if err := godotenv.Load(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not load dotenv file; check its permissions and KEY=value syntax")
	}
	return nil
}
