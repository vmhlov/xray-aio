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
	AmneziaWG    *AmneziaWGState    `json:"amneziawg,omitempty"`
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

// AmneziaWGState is the orchestrator-owned snapshot of the AmneziaWG
// install. Carries both halves of the keypair material (server +
// the single peer) so the subscription bundle can render a
// self-contained .conf for the client without needing an interactive
// "scan this QR" flow during install.
//
// Multi-peer is deferred to Phase 3 UX (xray-aio peer add/remove);
// in v1 a fresh `install` produces exactly one peer and the operator
// hands the bundle to one client. A subsequent rotate-style command
// will be able to add/revoke peers without invalidating the existing
// one.
//
// Persisting full obfuscation params (Jc/Jmin/Jmax/S1/S2/H1..H4) is
// what lets a re-run of `xray-aio install` keep the existing peer
// .conf valid: the client and server have to agree on the exact
// values, and re-randomizing them on every install would silently
// break previously distributed configs.
type AmneziaWGState struct {
	// Server-side keypair. PrivateKey is base64-encoded; PublicKey
	// is derived from it (kept in state.json so we don't have to
	// re-derive it on every Status/Probe call).
	ServerPrivateKey string `json:"server_private_key"`
	ServerPublicKey  string `json:"server_public_key"`

	// Peer-side keypair. The client receives PeerPrivateKey via
	// the rendered .conf; PeerPublicKey lives in the server's
	// [Peer] section and is what the AmneziaWG handshake matches
	// against.
	PeerPrivateKey string `json:"peer_private_key"`
	PeerPublicKey  string `json:"peer_public_key"`

	// PresharedKey strengthens forward secrecy; appears symmetrically
	// in the server's [Peer] section and the peer's .conf.
	PresharedKey string `json:"preshared_key"`

	// ListenPort is the UDP port the server binds.
	ListenPort int `json:"listen_port"`

	// ServerAddress / PeerAddress are the TUN interface addresses
	// (CIDR form) for each side. Persisted so re-installs don't
	// renumber the tunnel and break in-flight client connections.
	ServerAddress string `json:"server_address"`
	PeerAddress   string `json:"peer_address"`

	// MTU + DNS appear only in the peer's .conf; we keep them on
	// the server snapshot so the bundle renderer doesn't need its
	// own knob set.
	MTU int    `json:"mtu"`
	DNS string `json:"dns,omitempty"`

	// Obfuscation parameters. All fields are populated on first
	// install and persisted as-is.
	Jc   int    `json:"jc"`
	Jmin int    `json:"jmin"`
	Jmax int    `json:"jmax"`
	S1   int    `json:"s1"`
	S2   int    `json:"s2"`
	H1   uint32 `json:"h1"`
	H2   uint32 `json:"h2"`
	H3   uint32 `json:"h3"`
	H4   uint32 `json:"h4"`
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
