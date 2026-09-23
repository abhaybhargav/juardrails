package guardrail

import (
	"bytes"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteNamespaceIsolation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.SaveNamespace(Namespace{Name: "team", Description: "A team"}, true); err != nil {
		t.Fatal(err)
	}
	p := Policy{ID: "same", Name: "Root"}
	root, err := s.Save(p, true)
	if err != nil {
		t.Fatal(err)
	}
	p.Name = "Team"
	team, err := s.InNamespace("team").Save(p, true)
	if err != nil {
		t.Fatal(err)
	}
	root.Name = "Root v2"
	root, err = s.Save(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if root.Version != 2 || team.Version != 1 {
		t.Fatal("shared version counters")
	}
	got, _ := s.InNamespace("team").Get("same")
	if got.Name != "Team" || got.Namespace != "team" {
		t.Fatal(got)
	}
	revs, _ := s.InNamespace("team").Revisions("same")
	if len(revs) != 1 {
		t.Fatal("revision leak")
	}
	if _, err = s.InNamespace("team").Save(root, false); err == nil {
		t.Fatal("cross namespace write")
	}
	if err = s.Record(Evaluation{ID: "e", PolicyID: "same", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.InNamespace("team").Evaluation("e"); !errors.Is(err, ErrNotFound) {
		t.Fatal("evaluation leak")
	}
	if err = s.Delete("same", 2); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Save(p, true); !errors.Is(err, ErrConflict) {
		t.Fatal("deleted ID reused")
	}
	if _, err = s.InNamespace("team").Get("same"); err != nil {
		t.Fatal("cross namespace deletion")
	}
}
func TestLegacyImportPreservesHistories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")
	old, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := Policy{ID: "existing", Name: "Existing", Version: 2, CreatedAt: now, UpdatedAt: now}
	e := Evaluation{ID: "evaluation", PolicyID: p.ID, PolicyVersion: 1, CreatedAt: now}
	err = old.Update(func(tx *bolt.Tx) error {
		policies, _ := tx.CreateBucket([]byte("policies"))
		revisions, _ := tx.CreateBucket([]byte("revisions"))
		evaluations, _ := tx.CreateBucket([]byte("evaluations"))
		b, _ := json.Marshal(p)
		policies.Put([]byte(p.ID), b)
		for _, id := range []string{p.ID, "deleted"} {
			bucket, _ := revisions.CreateBucket([]byte(id))
			for v := 1; v <= 2; v++ {
				p.ID = id
				p.Version = v
				b, _ = json.Marshal(p)
				bucket.Put([]byte{byte(v)}, b)
			}
		}
		b, _ = json.Marshal(e)
		return evaluations.Put([]byte(e.ID), b)
	})
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	before, _ := os.ReadFile(path)
	s, err := Open(filepath.Join(dir, "new.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.ImportBolt(path); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("existing")
	if err != nil || got.Version != 2 || got.Namespace != "root" || !got.CreatedAt.Equal(now) {
		t.Fatal(got, err)
	}
	for _, id := range []string{"existing", "deleted"} {
		revs, err := s.Revisions(id)
		if err != nil || len(revs) != 2 {
			t.Fatal(revs, err)
		}
	}
	record, err := s.Evaluation("evaluation")
	if err != nil || record.PolicyVersion != 1 || record.Namespace != "root" {
		t.Fatal(record, err)
	}
	if _, err = s.Save(Policy{ID: "deleted"}, true); !errors.Is(err, ErrConflict) {
		t.Fatal("lost deleted history")
	}
	if err = s.ImportBolt(path); err == nil {
		t.Fatal("reimport allowed")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("source modified")
	}
}
