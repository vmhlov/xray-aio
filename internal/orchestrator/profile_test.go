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

func TestResolveProfileHomeMobile(t *testing.T) {
	t.Parallel()

	p, err := ResolveProfile("home-mobile")
	if err != nil {
		t.Fatalf("ResolveProfile(home-mobile): %v", err)
	}
	if p.Name != "home-mobile" {
		t.Errorf("Name: %q", p.Name)
	}
	got := p.Transports
	if len(got) != 3 || got[0] != "xray" || got[1] != "naive" || got[2] != "hysteria2" {
		t.Errorf("Transports: %v (want [xray naive hysteria2])", got)
	}
}

func TestProfileNeedsHysteria2(t *testing.T) {
	t.Parallel()

	if !profileNeedsHysteria2("home-mobile") {
		t.Error("home-mobile should need hysteria2")
	}
	if profileNeedsHysteria2("home-stealth") {
		t.Error("home-stealth should NOT need hysteria2")
	}
	if profileNeedsHysteria2("nope") {
		t.Error("unknown profile should NOT need hysteria2")
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
