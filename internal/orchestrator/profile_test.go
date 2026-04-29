package orchestrator

import (
	"strings"
	"testing"
)

func TestResolveProfileKnown(t *testing.T) {
	t.Parallel()

	p, err := ResolveProfile("home-stealth")
	if err != nil {
		t.Fatalf("ResolveProfile(home-stealth): %v", err)
	}
	if p.Name != "home-stealth" {
		t.Errorf("Name: %q", p.Name)
	}
	if got := p.Transports; len(got) != 2 || got[0] != "xray" || got[1] != "naive" {
		t.Errorf("Transports: %v (want [xray naive])", got)
	}
}

func TestResolveProfileUnknown(t *testing.T) {
	t.Parallel()

	_, err := ResolveProfile("nope")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(err.Error(), "home-stealth") {
		t.Errorf("error should list valid names: %v", err)
	}
}
