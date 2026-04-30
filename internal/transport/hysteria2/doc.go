// Package hysteria2 wires Hysteria 2 (https://v2.hysteria.network) into
// xray-aio's transport contract.
//
// Hysteria 2 is a UDP/QUIC tunnel. It listens on UDP/443 by default,
// which coexists with the TCP/443 REALITY listener (different L4
// protocols, no port conflict). On a misbehaving probe it can fall
// back to "masquerade" mode and proxy the QUIC handshake to a real
// HTTPS upstream — we point that at the same loopback selfsteal
// site Caddy already serves on :8443, so the masquerade behaviour
// stays consistent with what the REALITY upstream advertises.
//
// TLS strategy: hysteria2 reads its cert and key from disk on every
// handshake, so we point it at the certificates Caddy already stages
// under /var/lib/caddy/caddy/certificates/<acme-dir>/<domain>/. The
// hysteria2 service runs as the `caddy` system user (the same one
// the naive transport already created) so the read is a no-op
// permissions-wise, and we never duplicate ACME work.
//
// Operator inputs (Options.Extra):
//
//	hysteria2.password         string            (required)
//	hysteria2.listen_port      int               (default 443; UDP)
//	hysteria2.masquerade_url   string            (default https://127.0.0.1:8443)
//	hysteria2.cert_path        string            (default Caddy LE path for Domain)
//	hysteria2.key_path         string            (default Caddy LE path for Domain)
//
// The transport's init() registers a factory in the global registry
// under the name "hysteria2"; importing the package for side-effects
// from cmd/xray-aio is enough to make it visible to the orchestrator.
package hysteria2
