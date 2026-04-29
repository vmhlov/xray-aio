// Package state persists xray-aio runtime state to /etc/xray-aio/state.json.
//
// Phase 0: only schema and Load/Save with file locking. No business logic
// (UUID rotation, transport-specific fields) — those land in later phases.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultPath is the canonical state.json location on a system install.
// Tests and dev runs override via the XRAY_AIO_STATE env var.
const DefaultPath = "/etc/xray-aio/state.json"

// SchemaVersion is bumped on any backwards-incompatible change to State.
const SchemaVersion = 1

// State is the root document persisted across xray-aio invocations.
type State struct {
	Schema    int       `json:"schema"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Profile   string    `json:"profile,omitempty"`
	Domain    string    `json:"domain,omitempty"`

	// Transports holds per-transport configuration. Concrete shapes are
	// defined by each transport package and stored as opaque JSON here so
	// state.json stays decoupled from transport implementations.
	Transports map[string]json.RawMessage `json:"transports,omitempty"`
}

// Path returns the effective state.json location.
func Path() string {
	if p := os.Getenv("XRAY_AIO_STATE"); p != "" {
		return p
	}
	return DefaultPath
}

// Load reads the state file from Path(). If the file does not exist a
// freshly-initialised State (with current schema version) is returned.
func Load() (*State, error) {
	p := Path()
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		now := time.Now().UTC()
		return &State{Schema: SchemaVersion, CreatedAt: now, UpdatedAt: now}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if s.Schema == 0 {
		s.Schema = SchemaVersion
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("unsupported state schema: have %d want %d", s.Schema, SchemaVersion)
	}
	return &s, nil
}

// Save writes the state atomically to Path(). The file is created with
// 0600 permissions so it is unreadable by non-root users.
func Save(s *State) error {
	if s == nil {
		return errors.New("nil state")
	}
	s.UpdatedAt = time.Now().UTC()
	if s.Schema == 0 {
		s.Schema = SchemaVersion
	}
	p := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}
