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

// ProfileHomeVPN bundles NaïveProxy with AmneziaWG, the
// DPI-resistant WireGuard fork. Unlike the proxy-shaped profiles
// (home-stealth, home-mobile) which terminate per-connection on the
// server, this profile installs a layer-3 VPN: the client mounts a
// TUN interface and routes traffic through it.
//
// NaïveProxy is included alongside AmneziaWG for two reasons:
//   - it brings up Caddy with a Let's Encrypt cert so the
//     subscription bundle (HTML page + downloadable awg0.conf + QR)
//     is served over real HTTPS at https://<domain>:<naive-port>/sub/<token>/;
//   - it gives the operator a TCP-fallback knob for networks where
//     UDP is partly or wholly filtered. AmneziaWG uses UDP exclusively;
//     when UDP is blocked the operator can route the client over
//     Naive (proxy-shaped) until the network changes.
//
// Order matters: naive installs before amneziawg because the
// subscription bundle is staged into <naive-site-root>/sub/<token>/
// after both transports are up, and the AmneziaWG-side .conf
// rendering does not depend on Naive being installed first — but
// keeping the dependent-after-prerequisite invariant matches how
// home-mobile orders xray → naive → hysteria2.
var ProfileHomeVPN = Profile{
	Name:        "home-vpn",
	Description: "NaïveProxy (TCP fallback + bundle host) + AmneziaWG (DPI-resistant L3 VPN).",
	Transports:  []string{"naive", "amneziawg"},
}

// profiles is the registry of known profiles. Lookup is via [ResolveProfile].
var profiles = map[string]Profile{
	ProfileHomeStealth.Name: ProfileHomeStealth,
	ProfileHomeMobile.Name:  ProfileHomeMobile,
	ProfileHomeVPN.Name:     ProfileHomeVPN,
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
