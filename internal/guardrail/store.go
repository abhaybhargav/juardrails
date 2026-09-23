package guardrail

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("version conflict; reload the latest policy before saving")

type Store struct {
	db        *sql.DB
	namespace string
}
type Namespace struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

var namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}(/[a-z][a-z0-9_-]{0,63})*$`)

func ValidNamespace(n string) bool { return len(n) <= 255 && namespacePattern.MatchString(n) }
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	file.Close()
	if err = os.Chmod(path, 0600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	schema := `PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
 CREATE TABLE IF NOT EXISTS namespaces(name TEXT PRIMARY KEY,description TEXT NOT NULL,created_at TEXT NOT NULL);
 INSERT OR IGNORE INTO namespaces VALUES('root','Default namespace',strftime('%Y-%m-%dT%H:%M:%fZ','now'));
 CREATE TABLE IF NOT EXISTS policies(namespace TEXT NOT NULL REFERENCES namespaces(name),id TEXT NOT NULL,version INTEGER NOT NULL,document BLOB NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(namespace,id));
 CREATE TABLE IF NOT EXISTS revisions(namespace TEXT NOT NULL REFERENCES namespaces(name),id TEXT NOT NULL,version INTEGER NOT NULL,document BLOB NOT NULL,PRIMARY KEY(namespace,id,version));
 CREATE TABLE IF NOT EXISTS evaluations(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES namespaces(name),policy_id TEXT NOT NULL,created_at TEXT NOT NULL,document BLOB NOT NULL);
 CREATE INDEX IF NOT EXISTS evaluations_namespace_time ON evaluations(namespace,created_at DESC);
 CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);`
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize SQLite: %w", err)
	}
	return &Store{db: db, namespace: "root"}, nil
}
func (s *Store) DB() *sql.DB                 { return s.db }
func (s *Store) InNamespace(n string) *Store { return &Store{db: s.db, namespace: n} }
func (s *Store) Close() error                { return s.db.Close() }
func (s *Store) Get(id string) (Policy, error) {
	var p Policy
	var b []byte
	err := s.db.QueryRow("SELECT document FROM policies WHERE namespace=? AND id=?", s.namespace, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}
func (s *Store) List() ([]Policy, error) {
	out := []Policy{}
	rows, err := s.db.Query("SELECT document FROM policies WHERE namespace=? ORDER BY updated_at DESC,id", s.namespace)
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
func (s *Store) Save(p Policy, create bool) (Policy, error) {
	if p.Namespace != "" && p.Namespace != s.namespace {
		return p, fmt.Errorf("policy namespace must match the selected namespace")
	}
	p.Namespace = s.namespace
	tx, err := s.db.Begin()
	if err != nil {
		return p, err
	}
	defer tx.Rollback()
	var exists int
	if err = tx.QueryRow("SELECT count(*) FROM namespaces WHERE name=?", s.namespace).Scan(&exists); err != nil {
		return p, err
	}
	if exists != 1 {
		return p, ErrNotFound
	}
	var b []byte
	err = tx.QueryRow("SELECT document FROM policies WHERE namespace=? AND id=?", s.namespace, p.ID).Scan(&b)
	if create {
		if err == nil {
			return p, ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return p, err
		}
		if err = tx.QueryRow("SELECT count(*) FROM revisions WHERE namespace=? AND id=?", s.namespace, p.ID).Scan(&exists); err != nil {
			return p, err
		}
		if exists > 0 {
			return p, ErrConflict
		}
		p.Version = 1
		p.CreatedAt = time.Now().UTC()
	} else {
		if errors.Is(err, sql.ErrNoRows) {
			return p, ErrNotFound
		}
		if err != nil {
			return p, err
		}
		var old Policy
		if err = json.Unmarshal(b, &old); err != nil {
			return p, err
		}
		if p.Version != old.Version {
			return p, ErrConflict
		}
		p.Version++
		p.CreatedAt = old.CreatedAt
	}
	p.UpdatedAt = time.Now().UTC()
	b, err = json.Marshal(p)
	if err != nil {
		return p, err
	}
	if _, err = tx.Exec("INSERT INTO policies(namespace,id,version,document,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(namespace,id) DO UPDATE SET version=excluded.version,document=excluded.document,updated_at=excluded.updated_at", s.namespace, p.ID, p.Version, b, p.UpdatedAt.Format(time.RFC3339Nano)); err != nil {
		return p, err
	}
	if _, err = tx.Exec("INSERT INTO revisions VALUES(?,?,?,?)", s.namespace, p.ID, p.Version, b); err != nil {
		return p, err
	}
	return p, tx.Commit()
}
func (s *Store) Delete(id string, version int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int
	if err = tx.QueryRow("SELECT version FROM policies WHERE namespace=? AND id=?", s.namespace, id).Scan(&current); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if current != version {
		return ErrConflict
	}
	if _, err = tx.Exec("DELETE FROM policies WHERE namespace=? AND id=?", s.namespace, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Revisions(id string) ([]Policy, error) {
	out := []Policy{}
	rows, err := s.db.Query("SELECT document FROM revisions WHERE namespace=? AND id=? ORDER BY version", s.namespace, id)
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
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}
func (s *Store) Record(e Evaluation) error {
	e.Namespace = s.namespace
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("INSERT INTO evaluations VALUES(?,?,?,?,?)", e.ID, s.namespace, e.PolicyID, e.CreatedAt.Format(time.RFC3339Nano), b)
	return err
}
func (s *Store) Evaluations(id string, limit int) ([]Evaluation, error) {
	out := []Evaluation{}
	rows, err := s.db.Query("SELECT document FROM evaluations WHERE namespace=? AND (?='' OR policy_id=?) ORDER BY created_at DESC,id DESC LIMIT ?", s.namespace, id, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Evaluation
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) Evaluation(id string) (Evaluation, error) {
	var e Evaluation
	var b []byte
	err := s.db.QueryRow("SELECT document FROM evaluations WHERE namespace=? AND id=?", s.namespace, id).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(b, &e)
	return e, err
}
func (s *Store) Namespaces() ([]Namespace, error) {
	out := []Namespace{}
	rows, err := s.db.Query("SELECT name,description,created_at FROM namespaces ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var n Namespace
		var date string
		if err = rows.Scan(&n.Name, &n.Description, &date); err != nil {
			return nil, err
		}
		n.CreatedAt, _ = time.Parse(time.RFC3339Nano, date)
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) NamespaceExists(n string) bool {
	var count int
	return s.db.QueryRow("SELECT count(*) FROM namespaces WHERE name=?", n).Scan(&count) == nil && count == 1
}
func (s *Store) SaveNamespace(n Namespace, create bool) error {
	if !ValidNamespace(n.Name) || len(n.Description) > 2000 {
		return fmt.Errorf("invalid namespace name or description")
	}
	if create {
		if i := strings.LastIndex(n.Name, "/"); i >= 0 && !s.NamespaceExists(n.Name[:i]) {
			return fmt.Errorf("parent namespace must exist")
		}
		result, err := s.db.Exec("INSERT OR IGNORE INTO namespaces VALUES(?,?,?)", n.Name, n.Description, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
		count, _ := result.RowsAffected()
		if count == 0 {
			return ErrConflict
		}
		return nil
	}
	result, err := s.db.Exec("UPDATE namespaces SET description=? WHERE name=?", n.Description, n.Name)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
