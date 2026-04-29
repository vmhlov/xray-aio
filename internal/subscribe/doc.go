// Package subscribe builds end-user subscription artefacts:
//
//   - HMAC-tokenized URLs that map an opaque slug to a per-instance
//     subscription secret, so the URL is shareable but unguessable
//     and tamper-evident;
//   - protocol URI rendering for VLESS REALITY (Vision and XHTTP)
//     and NaïveProxy, matching the formats accepted by mainstream
//     clients (NekoBox, Hiddify, Streisand, Happ, Shadowrocket);
//   - a small HTML page (with one-click "Add to client" deep links)
//     served at /sub/<token> as a friendly landing.
//
// The HTTP serving layer is intentionally trivial — it is meant to be
// fronted by the same Caddy that serves the selfsteal page so we
// inherit its TLS, hide_listen ip, etc. Token plumbing lives here as
// pure functions so the orchestrator (Phase 1.6) can pick where to
// expose it.
package subscribe
