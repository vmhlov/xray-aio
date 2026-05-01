// Package amneziawg wires AmneziaWG (https://docs.amnezia.org/documentation/amnezia-wg/)
// into xray-aio's transport contract.
//
// AmneziaWG is a WireGuard fork that adds transport-level obfuscation
// against DPI: random "junk" packets prepended to handshakes,
// extra padding bytes injected into init/response messages, and
// magic-header substitutions (H1-H4) replacing WireGuard's fixed
// message-type numbers (1,2,3,4). With those parameters set the
// wire image stops matching standard WG signatures; with them all
// at zero/empty AmneziaWG is wire-compatible with vanilla
// WireGuard, but in this package we always randomize them — the
// whole point of integrating AmneziaWG instead of WireGuard is the
// DPI resistance, and a server that falls back to WG-compatible
// mode at config-render time would silently degrade to "regular WG"
// stealth (i.e. none).
//
// Runtime model: userspace amneziawg-go binary (Go fork of
// wireguard-go), launched as a systemd unit running as root with
// CAP_NET_ADMIN. We deliberately avoid the kernel-module path
// (PPA + DKMS + linux-headers + possible reboot) to match the
// hysteria2 deployment shape — single statically-built binary,
// pulled into /usr/local/bin once.
//
// AmneziaWG's wireline crypto is independent from any HTTPS
// listener — it does not consume the Caddy LE certificate, does
// not need to coexist on TCP/443, does not require Domain. The
// transport accepts Domain only because the orchestrator's
// transport.Options carries it and it shows up in the rendered
// peer .conf as the client Endpoint hostname (DNS friendlier than
// raw IPs).
//
// Operator inputs (Options.Extra):
//
//	amneziawg.private_key       string  (required, base64 32B Curve25519 secret)
//	amneziawg.peer_public_key   string  (required, base64 32B peer pubkey)
//	amneziawg.peer_preshared    string  (optional, base64 32B PSK)
//	amneziawg.server_address    string  (default 10.66.66.1/24)
//	amneziawg.peer_address      string  (default 10.66.66.2/32)
//	amneziawg.listen_port       int     (default 51842; UDP)
//	amneziawg.dns               string  (default 1.1.1.1, comma-separated for multi)
//	amneziawg.mtu               int     (default 1380; below WG's 1420 to absorb obfuscation overhead)
//	amneziawg.jc                int     (random 4-10 if unset)
//	amneziawg.jmin              int     (random 50-100 if unset)
//	amneziawg.jmax              int     (random Jmin+50..1000 if unset)
//	amneziawg.s1                int     (random 15-150 if unset)
//	amneziawg.s2                int     (random 15-150 if unset, never collides with S1)
//	amneziawg.h1                uint32  (random if unset; all of H1..H4 distinct, none in {1,2,3,4})
//	amneziawg.h2                uint32  (random if unset)
//	amneziawg.h3                uint32  (random if unset)
//	amneziawg.h4                uint32  (random if unset)
//
// The orchestrator generates keys + obfuscation params via Deps.Rand
// at first install and persists them in state.json so re-runs don't
// invalidate the peer's existing .conf. This package's Render only
// emits the bytes; randomization lives in keys.go and is driven by
// the orchestrator.
//
// Subscription bundle integration (peer .conf + QR + plain text)
// lands in a separate PR — this package only ships the server
// install + Render. The peer-side .conf format is symmetric to the
// server side (same H1-H4, S1/S2, Jc/Jmin/Jmax) and can be derived
// purely from the persisted state.
//
// The transport's init() registers a factory in the global registry
// under the name "amneziawg"; importing the package for side-effects
// from cmd/xray-aio is enough to make it visible to the orchestrator.
package amneziawg
