// Package tls owns the Caddy-based TLS frontend that all xray-aio
// transports terminate behind.
//
// Phase 1.2 ships:
//
//   - a Caddyfile template renderer with ACME via TLS-ALPN-01,
//     selfsteal landing page and HTTP→HTTPS redirect;
//   - an embedded "Hello from xray-aio" selfsteal page (replaceable
//     by the user via [Options.SelfStealHTML]);
//   - a [Manager] type that downloads a pinned Caddy release, writes
//     the configuration tree, installs a systemd unit and supervises
//     the service. The manager talks to the host through small
//     [Runner] / [Downloader] interfaces so the orchestrator's tests
//     can drive it without touching the real filesystem or network.
//
// Concrete transports (Xray REALITY, NaïveProxy, Trojan) plug into
// this Caddy installation in later phases by adding their own
// directives via [Manager.Reconfigure].
package tls
