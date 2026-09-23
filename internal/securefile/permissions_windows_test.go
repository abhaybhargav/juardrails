//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsCredentialACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".juardrails")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Protect(dir); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Protect(path); err != nil {
		t.Fatal(err)
	}
	if err := Check(path, false); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := Check(path, false); err == nil {
		t.Fatal("accepted credential accessible by Everyone")
	}
}
