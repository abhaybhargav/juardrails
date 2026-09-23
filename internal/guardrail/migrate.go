package guardrail

import (
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"time"
)

// ImportBolt copies the original store into an empty SQLite database. The source
// remains untouched. All rows and the migration marker commit atomically.
func (s *Store) ImportBolt(path string) error {
	source, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return err
	}
	defer source.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow("SELECT (SELECT count(*) FROM policies)+(SELECT count(*) FROM revisions)+(SELECT count(*) FROM evaluations)+(SELECT count(*) FROM metadata WHERE key='bolt_import')").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("legacy import requires an empty destination")
	}
	err = source.View(func(old *bolt.Tx) error {
		for _, name := range []string{"policies", "revisions", "evaluations"} {
			if old.Bucket([]byte(name)) == nil {
				return fmt.Errorf("invalid legacy database: missing %s", name)
			}
		}
		if err := old.Bucket([]byte("policies")).ForEach(func(_, b []byte) error {
			var p Policy
			if err := json.Unmarshal(b, &p); err != nil {
				return err
			}
			p.Namespace = "root"
			b, err := json.Marshal(p)
			if err != nil {
				return err
			}
			_, err = tx.Exec("INSERT INTO policies VALUES(?,?,?,?,?)", "root", p.ID, p.Version, b, p.UpdatedAt.Format(time.RFC3339Nano))
			return err
		}); err != nil {
			return err
		}
		if err := old.Bucket([]byte("revisions")).ForEach(func(k, _ []byte) error {
			bucket := old.Bucket([]byte("revisions")).Bucket(k)
			if bucket == nil {
				return fmt.Errorf("invalid legacy revision bucket")
			}
			return bucket.ForEach(func(_, b []byte) error {
				var p Policy
				if err := json.Unmarshal(b, &p); err != nil {
					return err
				}
				p.Namespace = "root"
				b, err := json.Marshal(p)
				if err != nil {
					return err
				}
				_, err = tx.Exec("INSERT INTO revisions VALUES(?,?,?,?)", "root", p.ID, p.Version, b)
				return err
			})
		}); err != nil {
			return err
		}
		return old.Bucket([]byte("evaluations")).ForEach(func(_, b []byte) error {
			var e Evaluation
			if err := json.Unmarshal(b, &e); err != nil {
				return err
			}
			e.Namespace = "root"
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			_, err = tx.Exec("INSERT INTO evaluations VALUES(?,?,?,?,?)", e.ID, "root", e.PolicyID, e.CreatedAt.Format(time.RFC3339Nano), b)
			return err
		})
	})
	if err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO metadata VALUES('bolt_import',?)", path); err != nil {
		return err
	}
	return tx.Commit()
}

// LegacyImportPending allows an interrupted initial import to be retried safely.
func (s *Store) LegacyImportPending() (bool, error) {
	var n int
	err := s.db.QueryRow("SELECT (SELECT count(*) FROM policies)+(SELECT count(*) FROM revisions)+(SELECT count(*) FROM evaluations)+(SELECT count(*) FROM metadata WHERE key='bolt_import')").Scan(&n)
	return n == 0, err
}
