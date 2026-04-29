package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	t.Setenv("XRAY_AIO_STATE", p)

	s1, err := Load()
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	if s1.Schema != SchemaVersion {
		t.Fatalf("schema=%d want %d", s1.Schema, SchemaVersion)
	}

	s1.Profile = "home-stealth"
	s1.Domain = "example.com"
	s1.Transports = map[string]json.RawMessage{
		"xray": json.RawMessage(`{"port":443}`),
	}
	if err := Save(s1); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("perm=%v want 0600", mode)
	}

	s2, err := Load()
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if s2.Profile != "home-stealth" || s2.Domain != "example.com" {
		t.Fatalf("roundtrip mismatch: %+v", s2)
	}
	var got map[string]int
	if err := json.Unmarshal(s2.Transports["xray"], &got); err != nil {
		t.Fatalf("unmarshal transport blob: %v", err)
	}
	if got["port"] != 443 {
		t.Fatalf("transport blob mismatch: %v", got)
	}
}

func TestLoadRejectsBadSchema(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	t.Setenv("XRAY_AIO_STATE", p)
	if err := os.WriteFile(p, []byte(`{"schema":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error on unsupported schema")
	}
}
