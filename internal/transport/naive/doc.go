// Package naive implements the NaïveProxy transport on top of Caddy
// with the forwardproxy plugin.
//
// Phase 1.7 unifies the package into the sole owner of Caddy in the
// xray-aio stack. A single Caddy instance terminates two HTTPS sites
// under the same domain and shares an ACME account + cert store via
// Caddy's auto-HTTPS:
//
//  1. <Domain>:<ListenPort> — the public NaïveProxy listener.
//     forward_proxy gated by basic_auth (with hide_ip / hide_via /
//     probe_resistance); unauthenticated requests fall through to a
//     static file_server so the listener is indistinguishable from a
//     vanilla webserver. Subscriptions are written under <SiteRoot>/sub/.
//
//  2. <Domain>:<SelfStealPort> — a loopback selfsteal site, file_server
//     only. This is the destination Xray REALITY relays a snooper to,
//     so it serves a valid LE-cert TLS handshake for <Domain> from a
//     directory distinct from <SiteRoot> (subscriptions never leak
//     through a REALITY relay).
//
// The package owns Caddyfile rendering with strict input validation
// (whitespace / quote / newline rejection on every interpolated
// field), the binary download (Caddy's official build service ships
// caddyserver/forwardproxy preloaded), the hardened systemd unit, and
// a [transport.Transport] adapter registered as "naive" so the
// orchestrator drives the whole lifecycle through one interface.
//
// Operators who need klzgrad's hardened @naive fork (additional
// probe-resistance fingerprints) should provide a custom build URL
// via Options.Extra at install time; that knob is exposed but not
// exercised by the default profile.
package naive
