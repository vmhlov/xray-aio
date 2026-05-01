package amneziawg

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultListenPort is the UDP port AmneziaWG listens on. Picked
// deliberately *not* to be the WG-canonical 51820 (which DPI knows
// to greylist on sight) and not to be 443/UDP (reserved for hy2 in
// the home-mobile profile, kept free in home-vpn for forward
// compatibility with profile combinations).
const DefaultListenPort = 51842

// DefaultServerAddress is the server-side TUN interface address +
// CIDR. /24 is plenty for a single-peer deploy and leaves room for
// multi-peer expansion in Phase 3 UX without renumbering.
const DefaultServerAddress = "10.66.66.1/24"

// DefaultPeerAddress is the address baked into the rendered peer
// .conf. /32 because the peer end only owns one IP on the tunnel.
const DefaultPeerAddress = "10.66.66.2/32"

// DefaultMTU sits below WireGuard's 1420 because AmneziaWG's
// padding parameters (S1/S2 and the junk packets) extend each
// outbound frame; clamping at 1380 keeps the post-obfuscation
// frame under the typical 1500-byte path MTU on consumer ISPs.
const DefaultMTU = 1380

// DefaultDNS is announced to the peer in its rendered config. The
// orchestrator overrides this when an operator passes
// `amneziawg.dns` in Options.Extra.
const DefaultDNS = "1.1.1.1"

// Config is the operator-facing knob set for one amneziawg install.
// Mirrors the wg-quick(8) config sections one-to-one — keep them in
// sync with [Render] / [RenderPeer].
type Config struct {
	// PrivateKey is the server's Curve25519 secret, base64 (32
	// raw bytes). Required.
	PrivateKey string

	// PeerPublicKey is the single peer's public key, base64.
	// Required for v1; multi-peer arrives in Phase 3 UX.
	PeerPublicKey string

	// PeerPresharedKey is optional. When non-empty it's emitted
	// in both the server's [Peer] section and the peer .conf.
	PeerPresharedKey string

	// ServerAddress is the server-side TUN interface CIDR.
	// Empty → DefaultServerAddress.
	ServerAddress string

	// PeerAddress is the address allowed for the peer. Both
	// server's [Peer].AllowedIPs and the peer's [Interface].Address
	// are derived from this. Empty → DefaultPeerAddress.
	PeerAddress string

	// ListenPort is the UDP port the server binds. 0 →
	// DefaultListenPort.
	ListenPort int

	// MTU is announced to the peer. 0 → DefaultMTU.
	MTU int

	// DNS is announced to the peer. Empty → DefaultDNS. May be
	// comma-separated.
	DNS string

	// Endpoint is the public dial string the peer .conf will
	// embed (typically "<Domain>:<ListenPort>" — the orchestrator
	// fills it from state.Domain). Used only by [RenderPeer];
	// the server's own config doesn't need it.
	Endpoint string

	// Obfuscation carries the AmneziaWG-specific transport-layer
	// parameters. ALL fields must be non-zero for the
	// obfuscation to actually engage; with H1..H4 left at zero
	// AmneziaWG silently degrades to wire-compatible WG, which
	// is the opposite of why we use it.
	Obfuscation Obfuscation
}

// Validate returns nil when cfg can be rendered. Pure data-shape
// checks; nothing that would touch the filesystem or hit the
// network.
func (c Config) Validate() error {
	if strings.TrimSpace(c.PrivateKey) == "" {
		return errors.New("amneziawg: PrivateKey is required")
	}
	if strings.TrimSpace(c.PeerPublicKey) == "" {
		return errors.New("amneziawg: PeerPublicKey is required")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("amneziawg: ListenPort %d out of range", c.ListenPort)
	}
	if c.MTU < 0 || c.MTU > 9000 {
		return fmt.Errorf("amneziawg: MTU %d out of range", c.MTU)
	}
	return c.Obfuscation.Validate()
}

// resolvedDefaults applies the package defaults to any unset Config
// field and returns the result. Both [Render] and [RenderPeer] go
// through it so the server and peer .conf agree byte-for-byte on
// the values that have to match.
func (c Config) resolvedDefaults() Config {
	if c.ServerAddress == "" {
		c.ServerAddress = DefaultServerAddress
	}
	if c.PeerAddress == "" {
		c.PeerAddress = DefaultPeerAddress
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.DNS == "" {
		c.DNS = DefaultDNS
	}
	return c
}

// Render emits the server-side `awg0.conf` consumed by `awg
// setconf`. Output is stable: config_test.go golden-tests against
// the exact bytes.
//
// Format follows wg-quick(8) (compatible with awg-quick(8) since
// AmneziaWG keeps the surface schema identical to WireGuard,
// adding only the obfuscation lines under [Interface]).
func Render(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	cfg = cfg.resolvedDefaults()

	var b strings.Builder
	b.WriteString("# Managed by xray-aio. Do not edit by hand — re-run `xray-aio install`.\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", cfg.ServerAddress)
	fmt.Fprintf(&b, "ListenPort = %d\n", cfg.ListenPort)
	writeObfuscation(&b, cfg.Obfuscation)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", cfg.PeerPublicKey)
	if cfg.PeerPresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", cfg.PeerPresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", cfg.PeerAddress)
	return b.String(), nil
}

// RenderPeer emits the peer-side `awg0.conf` an operator hands to
// the client (mobile AmneziaWG app, desktop AWG client, etc.).
// Format and obfuscation values mirror what Render produces — they
// MUST match for the handshake to succeed.
//
// PeerPrivateKey is the peer's secret (separate from the server's),
// passed as an argument because Config.PrivateKey is the server
// secret. ServerPublicKey is derived from Config.PrivateKey by the
// orchestrator and passed in here.
func RenderPeer(cfg Config, peerPrivateKey, serverPublicKey string) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(peerPrivateKey) == "" {
		return "", errors.New("amneziawg: peerPrivateKey is required")
	}
	if strings.TrimSpace(serverPublicKey) == "" {
		return "", errors.New("amneziawg: serverPublicKey is required")
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return "", errors.New("amneziawg: Endpoint is required for peer config")
	}
	cfg = cfg.resolvedDefaults()

	var b strings.Builder
	b.WriteString("# Managed by xray-aio. Import into AmneziaWG client (NOT vanilla WireGuard).\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", peerPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", cfg.PeerAddress)
	fmt.Fprintf(&b, "DNS = %s\n", cfg.DNS)
	fmt.Fprintf(&b, "MTU = %d\n", cfg.MTU)
	writeObfuscation(&b, cfg.Obfuscation)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	if cfg.PeerPresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", cfg.PeerPresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", cfg.Endpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String(), nil
}

// writeObfuscation appends the AmneziaWG-specific lines that have
// to appear in both [Interface] sections (server and peer). Order
// matches awg-quick(8) examples and amneziawg-go/README.md.
func writeObfuscation(b *strings.Builder, o Obfuscation) {
	fmt.Fprintf(b, "Jc = %d\n", o.Jc)
	fmt.Fprintf(b, "Jmin = %d\n", o.Jmin)
	fmt.Fprintf(b, "Jmax = %d\n", o.Jmax)
	fmt.Fprintf(b, "S1 = %d\n", o.S1)
	fmt.Fprintf(b, "S2 = %d\n", o.S2)
	fmt.Fprintf(b, "H1 = %d\n", o.H1)
	fmt.Fprintf(b, "H2 = %d\n", o.H2)
	fmt.Fprintf(b, "H3 = %d\n", o.H3)
	fmt.Fprintf(b, "H4 = %d\n", o.H4)
}
