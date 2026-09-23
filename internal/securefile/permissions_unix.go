//go:build !windows

package securefile

import (
	"fmt"
	"os"
)

// Check verifies that the path is the requested kind and is not group/world accessible.
func Check(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("credential path has the wrong type: %s", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential path must be private (0700 directory or 0600 file): %s", path)
	}
	return nil
}

// Protect is a no-op on Unix; creation uses private modes and Check verifies them.
func Protect(path string) error { return nil }
