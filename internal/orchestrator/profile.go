package orchestrator

import "fmt"

// Profile names a coordinated set of transports an operator can install
// in one call. New profiles plug in by adding to [profiles] and giving
// the install loop a Configure() that maps ProfileState → per-transport
// Options.
type Profile struct {
	Name        string
	Description string
	// Transports is the ordered list of registry names the
	// orchestrator drives. Order matters: TLS first, then dependent
	// transports. (Phase 1.6 home-stealth has a flat ordering: xray
	// then naive.)
	Transports []string
}

// ProfileHomeStealth is the canonical low-noise profile: VLESS REALITY
// (Vision) on :443 plus NaïveProxy on :8444. Phase 1.6 ships this
// minimum; selfsteal Caddy lands in Phase 1.7 once we have a unified
// Caddy binary that can serve both selfsteal and NaïveProxy from a
// single ACME-aware instance.
var ProfileHomeStealth = Profile{
	Name:        "home-stealth",
	Description: "VLESS REALITY (Vision) + NaïveProxy. TCP-only, low-noise.",
	Transports:  []string{"xray", "naive"},
}

// ProfileHomeMobile extends home-stealth with a Hysteria 2 (UDP/QUIC)
// listener that piggybacks on Caddy's LE cert. Order matters: naive
// must Install before hysteria2 so /var/lib/caddy/...<domain>.crt
// exists when hysteria2's systemd unit starts. Use this profile when
// UDP/443 is reachable from the client side; if the network blocks
// UDP, fall back to home-stealth (TCP-only).
var ProfileHomeMobile = Profile{
	Name:        "home-mobile",
	Description: "VLESS REALITY (Vision) + NaïveProxy + Hysteria 2 (UDP/QUIC).",
	Transports:  []string{"xray", "naive", "hysteria2"},
}

// profiles is the registry of known profiles. Lookup is via [ResolveProfile].
var profiles = map[string]Profile{
	ProfileHomeStealth.Name: ProfileHomeStealth,
	ProfileHomeMobile.Name:  ProfileHomeMobile,
}

// ResolveProfile returns the Profile by name or an error listing valid
// names. Used by Install().
func ResolveProfile(name string) (Profile, error) {
	if p, ok := profiles[name]; ok {
		return p, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q (known: %s)", name, knownProfileNames())
}

func knownProfileNames() string {
	out := ""
	for n := range profiles {
		if out != "" {
			out += ", "
		}
		out += n
	}
	return out
}
