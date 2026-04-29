package transport

import (
	"context"
	"errors"
	"testing"
)

type fakeTransport struct{ name string }

func (f *fakeTransport) Name() string                           { return f.name }
func (f *fakeTransport) Install(context.Context, Options) error { return nil }
func (f *fakeTransport) Start(context.Context) error            { return nil }
func (f *fakeTransport) Stop(context.Context) error             { return nil }
func (f *fakeTransport) Status(context.Context) (Status, error) { return Status{}, nil }
func (f *fakeTransport) Probe(context.Context) (ProbeResult, error) {
	return ProbeResult{OK: true}, nil
}
func (f *fakeTransport) Uninstall(context.Context) error { return nil }

func TestRegistryRoundtrip(t *testing.T) {
	resetRegistry(t)

	Register("alpha", func() Transport { return &fakeTransport{name: "alpha"} })
	Register("beta", func() Transport { return &fakeTransport{name: "beta"} })

	got := Names()
	want := []string{"alpha", "beta"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Names()=%v want %v", got, want)
	}

	tr, err := Get("alpha")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tr.Name() != "alpha" {
		t.Fatalf("Name=%q", tr.Name())
	}

	if _, err := Get("missing"); err == nil {
		t.Fatal("expected error for missing")
	}
}

func TestRegisterRejectsDuplicates(t *testing.T) {
	resetRegistry(t)
	Register("dup", func() Transport { return &fakeTransport{name: "dup"} })
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	Register("dup", func() Transport { return &fakeTransport{name: "dup"} })
}

func resetRegistry(t *testing.T) {
	t.Helper()
	regMu.Lock()
	registry = map[string]Factory{}
	regMu.Unlock()
}

// Suppress unused-import lint when errors package is imported but not used
// (kept for future tests).
var _ = errors.New
