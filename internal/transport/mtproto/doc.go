// Package mtproto wires Telegram's MTProto proxy with Fake-TLS
// (a.k.a. "EE-MTProxy") into xray-aio's transport contract.
//
// The underlying daemon is telemt (https://github.com/telemt/telemt),
// a Rust/Tokio reimplementation of Telegram's MTProxy that implements
// the "Fixed TLS ClientHello" / Fake-TLS mode understood by all modern
// Telegram clients (Desktop ≥ 6.7.2, recent Android/iOS). We pin a
// known-good release and verify its sha256 sidecar on download —
// upstream publishes both as release assets, so no custom build
// pipeline is needed (unlike AmneziaWG, which forced us to re-publish
// from source).
//
// Listen port: MTProto Fake-TLS wants a dedicated TCP port that
// speaks TLS-looking bytes. Our :443 TCP slot is taken by Xray's
// REALITY inbound and our :8443/:8444 slots by Caddy (selfsteal +
// naive forwardproxy), so the default is :8883 — the standard
// MQTT-over-TLS port, unobtrusive in traffic captures, and not
// in our existing collision set. Operators can override.
//
// Fake TLS domain: the `tls_domain` in telemt's config is the SNI
// the *client* sends and the cert-fingerprint the server emulates,
// not the operator's real hostname. We default to a well-known
// public TLS site (`www.microsoft.com`) so probes/emulation resolve
// cleanly; operators can override to any domain that is:
//  1. reachable from the VPS (for TLS emulation to fetch real cert
//     lengths on startup), and
//  2. not the operator's own domain (that'd be pointless — the
//     whole point of fake-TLS is to masquerade as someone else).
//
// Operator inputs (Options.Extra):
//
//	mtproto.secret        string   (required; 32 hex chars, 16 bytes)
//	mtproto.username      string   (default "xray-aio")
//	mtproto.listen_port   int      (default DefaultListenPort)
//	mtproto.tls_domain    string   (default DefaultTLSDomain)
//
// Phase 2.3 scope (this package): the transport package plus its
// registration in the global transport registry. Orchestrator
// wiring into a profile (CLI flags, subscription URI rendering,
// preflight collision checks) lands in Phase 2.3b, mirroring the
// Hysteria 2 split between #17 and #18.
package mtproto
