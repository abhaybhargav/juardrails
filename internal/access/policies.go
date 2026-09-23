package access

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

func (m *Manager) Policies() ([]Policy, error) {
	out := []Policy{}
	rows, err := m.db.Query("SELECT document FROM access_policies ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var p Policy
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (m *Manager) SavePolicy(p Policy, create bool) (Policy, error) {
	if !slug.MatchString(p.Name) || len(p.Description) > 2000 || len(p.Rules) == 0 || len(p.Rules) > 100 {
		return p, fmt.Errorf("valid name, description and 1–100 rules required")
	}
	for _, r := range p.Rules {
		n := strings.TrimSuffix(r.Namespace, "/**")
		if r.Namespace != "*" && (!namespace.MatchString(n) || len(n) > 255) {
			return p, fmt.Errorf("invalid namespace selector")
		}
		if len(r.Actions) == 0 || len(r.Actions) > len(Actions)+1 {
			return p, fmt.Errorf("actions required")
		}
		for _, a := range r.Actions {
			if a != "*" && !slices.Contains(Actions, a) {
				return p, fmt.Errorf("unknown action %q", a)
			}
		}
	}
	tx, err := m.db.Begin()
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	var version int
	err = tx.QueryRow("SELECT version FROM access_policies WHERE name=?", p.Name).Scan(&version)
	if create {
		if err == nil {
			return p, ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return p, err
		}
		if p.Version != 0 {
			return p, ErrConflict
		}
		if err = tx.QueryRow("SELECT COALESCE(MAX(version),0) FROM access_revisions WHERE name=?", p.Name).Scan(&version); err != nil {
			return p, err
		}
	} else {
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrNotFound
		}
		if err != nil {
			return p, err
		}
		if version != p.Version {
			return p, ErrConflict
		}
	}
	p.Version = version + 1
	b, _ := json.Marshal(p)
	if _, err = tx.Exec("INSERT INTO access_policies VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET version=excluded.version,document=excluded.document", p.Name, p.Version, b); err != nil {
		return p, err
	}
	if _, err = tx.Exec("INSERT INTO access_revisions VALUES(?,?,?)", p.Name, p.Version, b); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (m *Manager) DeletePolicy(name string, version int) error {
	res, err := m.db.Exec("DELETE FROM access_policies WHERE name=? AND version=?", name, version)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func (m *Manager) PolicyRevisions(name string) ([]Policy, error) {
	out := []Policy{}
	rows, err := m.db.Query("SELECT document FROM access_revisions WHERE name=? ORDER BY version DESC", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var p Policy
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (m *Manager) Bindings(id string) ([]string, error) {
	if _, err := m.Principal(id); err != nil {
		return nil, err
	}
	out := []string{}
	rows, err := m.db.Query("SELECT policy_name FROM bindings WHERE principal_id=? ORDER BY policy_name", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
func (m *Manager) Bind(id string, names []string) error {
	p, err := m.Principal(id)
	if err != nil {
		return err
	}
	if p.SuperAdmin {
		return fmt.Errorf("super-admin does not need policy bindings")
	}
	if len(names) > 100 {
		return fmt.Errorf("maximum 100 bindings")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, name := range names {
		var n int
		if err = tx.QueryRow("SELECT count(*) FROM access_policies WHERE name=?", name).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("access policy %q does not exist", name)
		}
	}
	if _, err = tx.Exec("DELETE FROM bindings WHERE principal_id=?", id); err != nil {
		return err
	}
	for _, name := range names {
		if _, err = tx.Exec("INSERT OR IGNORE INTO bindings VALUES(?,?)", id, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (m *Manager) Allowed(p Principal, ns, action string) bool {
	if p.Disabled || !slices.Contains(Actions, action) {
		return false
	}
	if p.SuperAdmin {
		return true
	}
	rows, err := m.db.Query("SELECT a.document FROM access_policies a JOIN bindings b ON b.policy_name=a.name WHERE b.principal_id=?", p.ID)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		var policy Policy
		if rows.Scan(&b) != nil || json.Unmarshal(b, &policy) != nil {
			return false
		}
		for _, r := range policy.Rules {
			match := r.Namespace == "*" || r.Namespace == ns
			if strings.HasSuffix(r.Namespace, "/**") {
				base := strings.TrimSuffix(r.Namespace, "/**")
				match = ns == base || strings.HasPrefix(ns, base+"/")
			}
			if match && (slices.Contains(r.Actions, "*") || slices.Contains(r.Actions, action)) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) Policy(name string) (Policy, error) {
	var p Policy
	var b []byte
	err := m.db.QueryRow("SELECT document FROM access_policies WHERE name=?", name).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}
