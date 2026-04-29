// Package naive implements the NaïveProxy transport on top of Caddy
// with the forwardproxy plugin.
//
// Phase 1.4 ships:
//
//   - a Caddyfile renderer for the canonical NaïveProxy server stanza
//     (forward_proxy + basic_auth + probe_resistance + a static
//     selfsteal site as fallback);
//   - input validation of every interpolated field (whitespace, quote,
//     newline rejection) so a hostile DOMAIN/USERNAME/PASSWORD can't
//     escape the template into arbitrary directives;
//   - a [Manager] that downloads a Caddy binary preloaded with the
//     forwardproxy plugin from the official build service, lays down
//     binary + Caddyfile + a hardened systemd unit, and supervises
//     it with systemctl;
//   - a [Transport] adapter registered as "naive" so the orchestrator
//     can drive it through the [transport.Transport] interface.
//
// This Caddy instance is *separate* from the selfsteal Caddy installed
// by the internal/tls package — they live under different paths
// (/usr/local/bin/caddy-naive vs /usr/local/bin/caddy), different
// systemd units (xray-aio-naive.service vs xray-aio-caddy.service)
// and different ports. Phase 1.5 orchestration arbitrates port
// allocation between them per profile.
//
// The plugin is the upstream caddyserver/forwardproxy. Operators who
// need klzgrad's hardened @naive fork (additional probe-resistance
// fingerprints) should provide a custom build URL via Options.Extra
// at install time; that knob is exposed but not exercised by the
// default profile.
package naive
