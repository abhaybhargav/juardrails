package access

import (
	"errors"
	"github.com/abhaybhargav/juardrails/internal/guardrail"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func manager(t *testing.T) (*Manager, *guardrail.Store) {
	t.Helper()
	s, err := guardrail.Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	m, err := New(s.DB())
	if err != nil {
		t.Fatal(err)
	}
	return m, s
}
func TestIdentityAndPasswordLifecycle(t *testing.T) {
	m, s := manager(t)
	admin, err := m.Bootstrap("admin", "a-strong-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Bootstrap("other", "a-strong-test-password"); err == nil {
		t.Fatal("second admin allowed")
	}
	if _, err = s.DB().Exec("DELETE FROM principals WHERE id=?", admin.ID); err == nil {
		t.Fatal("deleted superadmin")
	}
	if err = m.UpdatePrincipal(admin.ID, "", true); err == nil {
		t.Fatal("disabled superadmin")
	}
	p, err := m.CreatePrincipal("alice", "human", "Test human", "alice-password-long")
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	s.DB().QueryRow("SELECT password_hash FROM principals WHERE id=?", p.ID).Scan(&hash)
	if !strings.HasPrefix(hash, "$argon2id$") || strings.Contains(hash, "alice-password-long") {
		t.Fatal("password not hashed")
	}
	if _, err = m.Login("alice", "wrong", "ip"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	a, err := m.Login("alice", "alice-password-long", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(a.Secret); err != nil {
		t.Fatal(err)
	}
	if err = m.ChangePassword(p.ID, "wrong", "new-password-long", false); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err = m.ChangePassword(p.ID, "alice-password-long", "new-password-long", false); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(a.Secret); !errors.Is(err, ErrDenied) {
		t.Fatal("old session survived password change")
	}
	a, err = m.Login("alice", "new-password-long", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.UpdatePrincipal(p.ID, "", true); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(a.Secret); !errors.Is(err, ErrDenied) {
		t.Fatal("disabled user authenticated")
	}
	if err = m.UpdatePrincipal(p.ID, "", false); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(a.Secret); !errors.Is(err, ErrDenied) {
		t.Fatal("reenabling resurrected session")
	}
	for _, cfg := range []Settings{{Password: false, SessionMinutes: 480}, {Password: true, OTP: true, SessionMinutes: 480}, {Password: true, SSO: true, SessionMinutes: 480}, {Password: true, SessionMinutes: 0}} {
		if err = m.SaveSettings(cfg); err == nil {
			t.Fatal("invalid settings accepted", cfg)
		}
	}
	for i := 0; i < 11; i++ {
		_, err = m.Login("missing", "wrong", "other-ip")
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("no login throttling", err)
	}
}
func TestTokensAndNamespaceGrants(t *testing.T) {
	m, s := manager(t)
	p, err := m.CreatePrincipal("worker", "service", "", " ")
	if err == nil {
		t.Fatal("service password accepted")
	}
	p, err = m.CreatePrincipal("worker", "service", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.IssueServiceToken(p.ID, "missing-expiry", time.Time{}); err == nil {
		t.Fatal("missing expiry accepted")
	}
	if _, _, err = m.IssueServiceToken(p.ID, "too-long", time.Now().Add(366*24*time.Hour)); err == nil {
		t.Fatal("excess lifetime accepted")
	}
	tok, raw, err := m.IssueServiceToken(p.ID, "test", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	s.DB().QueryRow("SELECT hash FROM tokens WHERE id=?", tok.ID).Scan(&stored)
	if stored == raw || len(stored) != 64 {
		t.Fatal("token not hashed")
	}
	if _, err = m.Authenticate(raw); err != nil {
		t.Fatal(err)
	}
	if m.Allowed(p, "team", "policies:read") {
		t.Fatal("default allow")
	}
	policy, err := m.SavePolicy(Policy{Name: "reader", Rules: []Rule{{Namespace: "team/**", Actions: []string{"policies:read"}}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Bind(p.ID, []string{policy.Name}); err != nil {
		t.Fatal(err)
	}
	for _, ns := range []string{"team", "team/prod"} {
		if !m.Allowed(p, ns, "policies:read") {
			t.Fatal("denied subtree", ns)
		}
	}
	for _, ns := range []string{"root", "team-other", "teammate"} {
		if m.Allowed(p, ns, "policies:read") {
			t.Fatal("escaped subtree", ns)
		}
	}
	if m.Allowed(p, "team", "policies:update") {
		t.Fatal("ungranted action")
	}
	stale := policy
	policy.Rules[0].Namespace = "team"
	policy, err = m.SavePolicy(policy, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Allowed(p, "team/prod", "policies:read") {
		t.Fatal("revoked descendant access survived")
	}
	if _, err = m.SavePolicy(stale, false); !errors.Is(err, ErrConflict) {
		t.Fatal("stale update allowed")
	}
	if err = m.Bind(p.ID, []string{"missing"}); err == nil {
		t.Fatal("invalid binding allowed")
	}
	bound, _ := m.Bindings(p.ID)
	if len(bound) != 1 {
		t.Fatal("failed update changed bindings")
	}
	if err = m.DeletePolicy(policy.Name, policy.Version); err != nil {
		t.Fatal(err)
	}
	if m.Allowed(p, "team", "policies:read") {
		t.Fatal("deleted policy still grants")
	}
	bound, _ = m.Bindings(p.ID)
	if len(bound) != 0 {
		t.Fatal("bindings did not cascade")
	}
	if err = m.RevokeToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(raw); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked token accepted")
	}
	tok, raw, err = m.IssueServiceToken(p.ID, "expiry", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	s.DB().Exec("UPDATE tokens SET created_at=?,expires_at=? WHERE id=?", time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-time.Hour).Unix(), tok.ID)
	if _, err = m.Authenticate(raw); !errors.Is(err, ErrDenied) {
		t.Fatal("expired token accepted")
	}
}
