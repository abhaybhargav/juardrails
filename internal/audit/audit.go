// Package audit provides durable, append-only request events without request bodies or credentials.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	RemoteIP   string         `json:"remote_ip,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	Time       time.Time      `json:"time"`
	RequestID  string         `json:"request_id,omitempty"`
	Phase      string         `json:"phase"`
	ActorID    string         `json:"actor_id,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	ActorKind  string         `json:"actor_kind,omitempty"`
	TokenID    string         `json:"token_id,omitempty"`
	Method     string         `json:"method,omitempty"`
	Resource   string         `json:"resource,omitempty"`
	Namespace  string         `json:"namespace,omitempty"`
	Action     string         `json:"action"`
	Target     string         `json:"target,omitempty"`
	Version    int            `json:"version,omitempty"`
	Status     int            `json:"status,omitempty"`
	DurationMS int64          `json:"duration_ms,omitempty"`
}
type Logger struct {
	mu   sync.Mutex
	file *os.File
}

func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return &Logger{file: f}, nil
}
func (l *Logger) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Time = time.Now().UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err = l.file.Write(b); err != nil {
		return err
	}
	return l.file.Sync()
}
func (l *Logger) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
