// Package xray implements the VLESS REALITY transport on top of
// XTLS/Xray-core.
//
// Phase 1.3 ships:
//
//   - a config builder for the two canonical stealth modes,
//     [ModeVision] (TCP + xtls-rprx-vision) and [ModeXHTTP]
//     (HTTP/2 framing inside REALITY);
//   - x25519 keypair, UUIDv4, short-id generators that match what
//     `xray x25519` / `xray uuid` would emit so we don't shell out to
//     the binary for setup;
//   - a [Manager] that downloads a pinned Xray-core release, lays
//     down the binary, config and a hardened systemd unit, and
//     supervises it via systemctl;
//   - a [Transport] adapter registered as "xray" in the global
//     transport registry so the orchestrator can drive it through
//     the [transport.Transport] interface.
//
// Wiring with the Caddy frontend (REALITY dest=127.0.0.1:8443 with
// Caddy serving the selfsteal page on that port) lands in Phase 1.5.
package xray
