package orchestrator

import (
	"encoding/json"
	"fmt"

	"github.com/vmhlov/xray-aio/internal/state"
)

// stateKey is the bucket under state.Transports where the orchestrator
// stores its per-profile derived data. Individual transport packages
// own their own buckets ("xray", "naive", ...) — this one captures the
// inputs the orchestrator generated (UUIDs, keys, credentials,
// subscription secret/token) so a future xray-aio rotate / status can
// reproduce the same install without re-asking the operator.
const stateKey = "_orchestrator"

// ProfileState is the on-disk shape persisted under state.Transports[stateKey].
type ProfileState struct {
	Profile string `json:"profile"`
	Domain  string `json:"domain"`
	Email   string `json:"email,omitempty"`

	Xray         *XrayState         `json:"xray,omitempty"`
	Naive        *NaiveState        `json:"naive,omitempty"`
	Hysteria2    *Hysteria2State    `json:"hysteria2,omitempty"`
	Subscription *SubscriptionState `json:"subscription,omitempty"`
}

// XrayState is the orchestrator-owned snapshot of the Xray REALITY
// install. Mirrors the inputs used for transport.Install plus the
// listening port so status/probe can reach back without parsing the
// rendered config a second time.
type XrayState struct {
	Mode       string   `json:"mode"`
	UUID       string   `json:"uuid"`
	PrivateKey string   `json:"private_key"`
	PublicKey  string   `json:"public_key"`
	ShortIDs   []string `json:"short_ids"`
	ListenPort int      `json:"listen_port"`
	Dest       string   `json:"dest"`
	XHTTPPath  string   `json:"xhttp_path,omitempty"`
}

// NaiveState is the orchestrator-owned snapshot of the Naive install.
type NaiveState struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ListenPort      int    `json:"listen_port"`
	ProbeResistance string `json:"probe_resistance,omitempty"`
	SiteRoot        string `json:"site_root"`
	SelfStealPort   int    `json:"selfsteal_port,omitempty"`
	SelfStealRoot   string `json:"selfsteal_root,omitempty"`
}

// Hysteria2State is the orchestrator-owned snapshot of the Hysteria 2
// install. Cert reuse follows the home-mobile profile contract: the
// hysteria2 systemd unit reads Caddy's LE cert in /var/lib/caddy/...,
// so we don't persist cert/key paths here — the transport derives
// them from Domain.
type Hysteria2State struct {
	Password      string `json:"password"`
	ListenPort    int    `json:"listen_port"`
	MasqueradeURL string `json:"masquerade_url,omitempty"`
}

// SubscriptionState is the per-host subscription secret plus the token
// minted for the default client. Multi-client / revocation lands in a
// later phase.
type SubscriptionState struct {
	// Secret is base64.RawURL-encoded so it round-trips through JSON
	// without binary smuggling.
	Secret string `json:"secret"`

	// DefaultClientID is the client-id used by Install() to mint the
	// canonical token that the operator hands out.
	DefaultClientID string `json:"default_client_id"`

	// Token is the rendered "<id>.<tag>" form. Path component on disk
	// is `<naive_site_root>/sub/<Token>/index.html`.
	Token string `json:"token"`
}

// loadProfileState extracts the orchestrator's slice from a [state.State].
// Returns nil (with no error) when the slice has not been written yet.
func loadProfileState(s *state.State) (*ProfileState, error) {
	if s == nil || s.Transports == nil {
		return nil, nil
	}
	raw, ok := s.Transports[stateKey]
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	var ps ProfileState
	if err := json.Unmarshal(raw, &ps); err != nil {
		return nil, fmt.Errorf("parse %s state: %w", stateKey, err)
	}
	return &ps, nil
}

// saveProfileState writes ps into s under stateKey, creating the
// transports map on first use.
func saveProfileState(s *state.State, ps *ProfileState) error {
	if s == nil {
		return fmt.Errorf("nil state")
	}
	if ps == nil {
		return fmt.Errorf("nil profile state")
	}
	raw, err := json.Marshal(ps)
	if err != nil {
		return fmt.Errorf("marshal %s state: %w", stateKey, err)
	}
	if s.Transports == nil {
		s.Transports = map[string]json.RawMessage{}
	}
	s.Transports[stateKey] = raw
	s.Profile = ps.Profile
	s.Domain = ps.Domain
	return nil
}
