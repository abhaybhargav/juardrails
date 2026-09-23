package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

var ErrDenied = errors.New("invalid credentials or expired token")
var ErrConflict = errors.New("resource already exists or version conflict")
var ErrNotFound = errors.New("not found")
var ErrRateLimited = errors.New("too many login attempts; try again later")

type Principal struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Description string    `json:"description"`
	SuperAdmin  bool      `json:"super_admin"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
}
type Rule struct {
	Namespace string   `json:"namespace"`
	Actions   []string `json:"actions"`
}
type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
	Version     int    `json:"version"`
}
type Token struct {
	ID          string    `json:"id"`
	PrincipalID string    `json:"principal_id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Revoked     bool      `json:"revoked"`
}
type Session struct {
	Principal Principal
	Token     Token
	Secret    string
}
type Settings struct {
	Password       bool `json:"password"`
	OTP            bool `json:"otp"`
	SSO            bool `json:"sso"`
	SessionMinutes int  `json:"session_minutes"`
}
type Manager struct {
	db    *sql.DB
	dummy string
	slots chan struct{}
}

var slug = regexp.MustCompile(`^[a-z][a-z0-9_.@-]{0,127}$`)
var namespace = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}(/[a-z][a-z0-9_-]{0,63})*$`)
var Actions = []string{"policies:read", "policies:create", "policies:update", "policies:delete", "policies:evaluate", "policies:simulate", "evaluations:read"}

func New(db *sql.DB) (*Manager, error) {
	schema := `CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,kind TEXT NOT NULL CHECK(kind IN ('human','service')),description TEXT NOT NULL DEFAULT '',super_admin INTEGER NOT NULL DEFAULT 0 CHECK(super_admin IN(0,1)),disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1)),password_hash TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL,CHECK(super_admin=0 OR(kind='human' AND disabled=0)));
 CREATE UNIQUE INDEX IF NOT EXISTS one_super_admin ON principals(super_admin) WHERE super_admin=1;
 CREATE TRIGGER IF NOT EXISTS protect_super_admin_delete BEFORE DELETE ON principals WHEN OLD.super_admin=1 BEGIN SELECT RAISE(ABORT,'super-admin cannot be deleted'); END;
 CREATE TRIGGER IF NOT EXISTS protect_super_admin_role BEFORE UPDATE OF super_admin,kind,disabled,id ON principals WHEN OLD.super_admin=1 BEGIN SELECT RAISE(ABORT,'super-admin identity cannot be changed'); END;
 CREATE TABLE IF NOT EXISTS access_policies(name TEXT PRIMARY KEY,version INTEGER NOT NULL,document BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS access_revisions(name TEXT NOT NULL,version INTEGER NOT NULL,document BLOB NOT NULL,PRIMARY KEY(name,version));
 CREATE TABLE IF NOT EXISTS bindings(principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,policy_name TEXT NOT NULL REFERENCES access_policies(name) ON DELETE CASCADE,PRIMARY KEY(principal_id,policy_name));
 CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,hash TEXT NOT NULL UNIQUE,principal_id TEXT NOT NULL REFERENCES principals(id),name TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('session','service')),expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,CHECK(expires_at>created_at));
 CREATE TABLE IF NOT EXISTS auth_settings(id INTEGER PRIMARY KEY CHECK(id=1),document BLOB NOT NULL);
 INSERT OR IGNORE INTO auth_settings VALUES(1,'{"password":true,"otp":false,"sso":false,"session_minutes":480}');
 CREATE TABLE IF NOT EXISTS login_limits(key TEXT PRIMARY KEY,attempts INTEGER NOT NULL,reset_at INTEGER NOT NULL);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	dummy, err := HashPassword("dummy-password-never-used")
	if err != nil {
		return nil, err
	}
	return &Manager{db: db, dummy: dummy, slots: make(chan struct{}, 4)}, nil
}
func secret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func GenerateSecret() string { return secret(32) }
func digest(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func CSRF(s string) string   { return digest("csrf:" + s) }
func HashPassword(password string) (string, error) {
	if len(password) < 12 || len(password) > 256 {
		return "", fmt.Errorf("password must be 12–256 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return "$argon2id$v=19$m=19456,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}
func verify(hash, password string) bool {
	if len(password) > 256 {
		return false
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=19456,t=2,p=1" {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (m *Manager) NeedsBootstrap() (bool, error) {
	var n int
	err := m.db.QueryRow("SELECT count(*) FROM principals WHERE super_admin=1").Scan(&n)
	return n == 0, err
}
func (m *Manager) Bootstrap(name, password string) (Principal, error) {
	var p Principal
	if !slug.MatchString(name) {
		return p, fmt.Errorf("invalid admin username")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return p, err
	}
	p = Principal{ID: secret(16), Name: name, Kind: "human", SuperAdmin: true, CreatedAt: time.Now().UTC()}
	_, err = m.db.Exec("INSERT INTO principals(id,name,kind,description,super_admin,password_hash,created_at) VALUES(?,?,?,'Platform super-admin',1,?,?)", p.ID, p.Name, p.Kind, hash, p.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return Principal{}, ErrConflict
	}
	return p, nil
}
func scanPrincipal(row interface{ Scan(...any) error }) (Principal, error) {
	var p Principal
	var created string
	err := row.Scan(&p.ID, &p.Name, &p.Kind, &p.Description, &p.SuperAdmin, &p.Disabled, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return p, err
}

const principalColumns = "id,name,kind,description,super_admin,disabled,created_at"

func (m *Manager) Principal(id string) (Principal, error) {
	return scanPrincipal(m.db.QueryRow("SELECT "+principalColumns+" FROM principals WHERE id=?", id))
}
func (m *Manager) Principals() ([]Principal, error) {
	out := []Principal{}
	rows, err := m.db.Query("SELECT " + principalColumns + " FROM principals ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (m *Manager) CreatePrincipal(name, kind, description, password string) (Principal, error) {
	var p Principal
	if !slug.MatchString(name) || len(description) > 2000 {
		return p, fmt.Errorf("invalid name or description")
	}
	if kind != "human" && kind != "service" {
		return p, fmt.Errorf("kind must be human or service")
	}
	hash := ""
	var err error
	if kind == "human" {
		hash, err = HashPassword(password)
		if err != nil {
			return p, err
		}
	} else if password != "" {
		return p, fmt.Errorf("service accounts cannot have passwords")
	}
	p = Principal{ID: secret(16), Name: name, Kind: kind, Description: description, CreatedAt: time.Now().UTC()}
	result, err := m.db.Exec("INSERT OR IGNORE INTO principals(id,name,kind,description,password_hash,created_at) VALUES(?,?,?,?,?,?)", p.ID, name, kind, description, hash, p.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return p, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return p, ErrConflict
	}
	return p, nil
}
func (m *Manager) UpdatePrincipal(id, description string, disabled bool) error {
	p, err := m.Principal(id)
	if err != nil {
		return err
	}
	if p.SuperAdmin {
		return fmt.Errorf("super-admin identity is permanent; use change password")
	}
	if len(description) > 2000 {
		return fmt.Errorf("description is too long")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE principals SET description=?,disabled=? WHERE id=?", description, disabled, id); err != nil {
		return err
	}
	if disabled {
		if _, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE principal_id=?", id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (m *Manager) DeletePrincipal(id string) error {
	p, err := m.Principal(id)
	if err != nil {
		return err
	}
	if p.SuperAdmin {
		return fmt.Errorf("super-admin identity is permanent")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM tokens WHERE principal_id=?", id); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM bindings WHERE principal_id=?", id); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM principals WHERE id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}
func (m *Manager) ChangePassword(id, current, next string, adminReset bool) error {
	p, err := m.Principal(id)
	if err != nil {
		return err
	}
	if p.Kind != "human" {
		return fmt.Errorf("only human accounts have passwords")
	}
	var old string
	if err = m.db.QueryRow("SELECT password_hash FROM principals WHERE id=?", id).Scan(&old); err != nil {
		return err
	}
	if !adminReset && !verify(old, current) {
		return ErrDenied
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE principals SET password_hash=? WHERE id=? AND password_hash=?", hash, id, old)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrConflict
	}
	if _, err = tx.Exec("UPDATE tokens SET revoked=1 WHERE principal_id=?", id); err != nil {
		return err
	}
	return tx.Commit()
}
func (m *Manager) Settings() (Settings, error) {
	var cfg Settings
	var b []byte
	err := m.db.QueryRow("SELECT document FROM auth_settings WHERE id=1").Scan(&b)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(b, &cfg)
	return cfg, err
}
func (m *Manager) SaveSettings(cfg Settings) error {
	if !cfg.Password || cfg.OTP || cfg.SSO {
		return fmt.Errorf("password authentication must remain enabled; OTP and SSO are not implemented")
	}
	if cfg.SessionMinutes < 5 || cfg.SessionMinutes > 1440 {
		return fmt.Errorf("session_minutes must be between 5 and 1440")
	}
	b, _ := json.Marshal(cfg)
	_, err := m.db.Exec("UPDATE auth_settings SET document=? WHERE id=1", b)
	return err
}
func (m *Manager) loginAttempt(key string, max int) error {
	now := time.Now().Unix()
	if _, err := m.db.Exec("DELETE FROM login_limits WHERE reset_at<=?", now); err != nil {
		return err
	}
	var count int
	err := m.db.QueryRow(`INSERT INTO login_limits(key,attempts,reset_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN reset_at<=? THEN 1 ELSE attempts+1 END,reset_at=CASE WHEN reset_at<=? THEN ? ELSE reset_at END RETURNING attempts`, digest(key), now+900, now, now, now+900).Scan(&count)
	if err != nil {
		return err
	}
	if count > max {
		return ErrRateLimited
	}
	return nil
}
func (m *Manager) Login(name, password, ip string) (Session, error) {
	var session Session
	select {
	case m.slots <- struct{}{}:
		defer func() { <-m.slots }()
	default:
		return session, ErrRateLimited
	}
	if err := m.loginAttempt("ip:"+ip, 60); err != nil {
		return session, err
	}
	if err := m.loginAttempt("name:"+strings.ToLower(name), 10); err != nil {
		return session, err
	}
	cfg, err := m.Settings()
	if err != nil {
		return session, err
	}
	if !cfg.Password {
		return session, ErrDenied
	}
	var id, hash string
	var disabled bool
	err = m.db.QueryRow("SELECT id,password_hash,disabled FROM principals WHERE name=? AND kind='human'", name).Scan(&id, &hash, &disabled)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return session, err
		}
		verify(m.dummy, password)
		return session, ErrDenied
	}
	if !verify(hash, password) || disabled {
		return session, ErrDenied
	}
	// Mint within a transaction that rechecks the password, preventing a password
	// reset or disable racing with login from producing a fresh valid session.
	tx, err := m.db.Begin()
	if err != nil {
		return session, err
	}
	defer tx.Rollback()
	var current string
	if err = tx.QueryRow("SELECT password_hash FROM principals WHERE id=? AND disabled=0", id).Scan(&current); err != nil || current != hash {
		return session, ErrDenied
	}
	token, raw, err := mint(tx, id, "Password session", "session", time.Now().Add(time.Duration(cfg.SessionMinutes)*time.Minute))
	if err != nil {
		return session, err
	}
	if _, err = tx.Exec("DELETE FROM login_limits WHERE key=?", digest("name:"+strings.ToLower(name))); err != nil {
		return session, err
	}
	if err = tx.Commit(); err != nil {
		return session, err
	}
	p, err := m.Principal(id)
	return Session{Principal: p, Token: token, Secret: raw}, err
}
func mint(tx *sql.Tx, id, name, kind string, expires time.Time) (Token, string, error) {
	now := time.Now().UTC()
	token := Token{ID: secret(16), PrincipalID: id, Name: name, Kind: kind, ExpiresAt: expires.UTC().Truncate(time.Second), CreatedAt: now.Truncate(time.Second)}
	raw := "jrd_" + secret(32)
	_, err := tx.Exec("INSERT INTO tokens(id,hash,principal_id,name,kind,expires_at,created_at) VALUES(?,?,?,?,?,?,?)", token.ID, digest(raw), id, name, kind, token.ExpiresAt.Unix(), now.Unix())
	return token, raw, err
}
func (m *Manager) IssueServiceToken(id, name string, expires time.Time) (Token, string, error) {
	if strings.TrimSpace(name) == "" || len(name) > 160 {
		return Token{}, "", fmt.Errorf("token name is required (maximum 160 characters)")
	}
	now := time.Now()
	if !expires.After(now.Add(time.Second)) || expires.After(now.Add(365*24*time.Hour)) {
		return Token{}, "", fmt.Errorf("expires_at is required and must be in the future, at most 365 days away")
	}
	tx, err := m.db.Begin()
	if err != nil {
		return Token{}, "", err
	}
	defer tx.Rollback()
	var kind string
	err = tx.QueryRow("SELECT kind FROM principals WHERE id=? AND disabled=0", id).Scan(&kind)
	if err != nil || kind != "service" {
		return Token{}, "", fmt.Errorf("tokens can only be issued to enabled service accounts")
	}
	t, raw, err := mint(tx, id, name, "service", expires)
	if err != nil {
		return Token{}, "", err
	}
	return t, raw, tx.Commit()
}
func (m *Manager) Authenticate(raw string) (Session, error) {
	var session Session
	if len(raw) > 128 || !strings.HasPrefix(raw, "jrd_") {
		return session, ErrDenied
	}
	var t Token
	var expires, created int64
	err := m.db.QueryRow("SELECT id,principal_id,name,kind,expires_at,created_at,revoked FROM tokens WHERE hash=?", digest(raw)).Scan(&t.ID, &t.PrincipalID, &t.Name, &t.Kind, &expires, &created, &t.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return session, ErrDenied
	}
	if err != nil {
		return session, err
	}
	if t.Revoked || expires <= time.Now().Unix() {
		return session, ErrDenied
	}
	p, err := m.Principal(t.PrincipalID)
	if err != nil || p.Disabled {
		return session, ErrDenied
	}
	if (t.Kind == "service") != (p.Kind == "service") {
		return session, ErrDenied
	}
	t.ExpiresAt = time.Unix(expires, 0).UTC()
	t.CreatedAt = time.Unix(created, 0).UTC()
	return Session{Principal: p, Token: t, Secret: raw}, nil
}
func (m *Manager) Tokens() ([]Token, error) {
	out := []Token{}
	rows, err := m.db.Query("SELECT id,principal_id,name,kind,expires_at,created_at,revoked FROM tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t Token
		var expires, created int64
		if err = rows.Scan(&t.ID, &t.PrincipalID, &t.Name, &t.Kind, &expires, &created, &t.Revoked); err != nil {
			return nil, err
		}
		t.ExpiresAt = time.Unix(expires, 0).UTC()
		t.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}
func (m *Manager) RevokeToken(id string) error {
	res, err := m.db.Exec("UPDATE tokens SET revoked=1 WHERE id=?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
