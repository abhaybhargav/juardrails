//go:build windows

package securefile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// Protect replaces inherited access with full control for the current user,
// SYSTEM, and Administrators. Call it before writing a credential secret.
func Protect(path string) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// Check rejects credential paths with grants to identities other than the
// current user, SYSTEM, or Administrators. POSIX mode bits are not ACLs on Windows.
func Check(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("credential path has the wrong type: %s", path)
	}
	sid, err := currentSID()
	if err != nil {
		return err
	}
	allowed := map[string]bool{sid: true, "S-1-5-18": true, "S-1-5-32-544": true}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("cannot inspect credential ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("credential path needs a private ACL: %s", path)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			return fmt.Errorf("credential ACL contains an unsupported grant: %s", path)
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[aceSID.String()] {
			return fmt.Errorf("credential ACL grants another identity: %s", path)
		}
	}
	return nil
}
