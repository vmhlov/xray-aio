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
	if !profileNeedsHysteria2("home-vpn-mobile") {
		t.Error("home-vpn-mobile should need hysteria2 (full-stack profile)")
	}
	if profileNeedsHysteria2("home-stealth") {
		t.Error("home-stealth should NOT need hysteria2")
	}
	if profileNeedsHysteria2("home-vpn") {
		t.Error("home-vpn should NOT need hysteria2")
	}
	if profileNeedsHysteria2("nope") {
		t.Error("unknown profile should NOT need hysteria2")
	}
}

// home-vpn-mobile is the union of home-mobile and home-vpn,
// staged at the end of Phase 2.2 once amneziawg's runtime issues
// (PR #33 wg-quick directives + PR #34 UAPI socket race) had been
// shaken out by live test on Debian 11. The expected transport
// list — xray then naive then hysteria2 then amneziawg — matches
// the order the install loop must drive: xray + naive bring up
// the TLS cert that hysteria2 piggybacks on, and amneziawg lands
// last so its UAPI-socket wait loop runs after the rest of the
// stack has settled.
func TestResolveProfileHomeVPNMobile(t *testing.T) {
	t.Parallel()

	p, err := ResolveProfile("home-vpn-mobile")
	if err != nil {
		t.Fatalf("ResolveProfile(home-vpn-mobile): %v", err)
	}
	if p.Name != "home-vpn-mobile" {
		t.Errorf("Name: %q", p.Name)
	}
	want := []string{"xray", "naive", "hysteria2", "amneziawg"}
	if len(p.Transports) != len(want) {
		t.Fatalf("Transports len: got %v, want %v", p.Transports, want)
	}
	for i, tr := range want {
		if p.Transports[i] != tr {
			t.Errorf("Transports[%d]: %q, want %q", i, p.Transports[i], tr)
		}
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
