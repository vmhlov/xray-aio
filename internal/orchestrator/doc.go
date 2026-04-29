// Package orchestrator coordinates the per-profile install of all
// transports the operator selected. It owns the high-level workflow:
//
//  1. Preflight environment.
//  2. Generate or reuse per-host secrets (UUIDs, x25519 keys, naive
//     credentials, subscription HMAC secret).
//  3. Drive each transport's Install() in dependency order.
//  4. Build a subscribe.Bundle and render it onto disk so an existing
//     transport's Caddy file_server publishes /sub/<token>/.
//  5. Persist everything to state.json.
//
// Phase 1.6 ships the home-stealth profile (Xray REALITY + Naive).
// Selfsteal Caddy and additional profiles land in subsequent phases.
package orchestrator
