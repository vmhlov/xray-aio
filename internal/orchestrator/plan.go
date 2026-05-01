package orchestrator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/vmhlov/xray-aio/internal/subscribe"
	amneziawgtransport "github.com/vmhlov/xray-aio/internal/transport/amneziawg"
	hysteria2transport "github.com/vmhlov/xray-aio/internal/transport/hysteria2"
	naivetransport "github.com/vmhlov/xray-aio/internal/transport/naive"
	xraytransport "github.com/vmhlov/xray-aio/internal/transport/xray"
)

// generatePlan returns a fresh ProfileState for opts. All randomness
// is drawn from rng — production callers pass crypto/rand, tests pass
// a deterministic reader.
//
// Defaults applied here:
//   - Xray: Vision mode, port 443, dest 127.0.0.1:8443, one short id.
//   - Naive: 16-byte hex username/password, port 8444.
//   - Hysteria 2: 32-byte base64.RawURL password, port 443/UDP,
//     selfsteal-domain masquerade.
//   - AmneziaWG: Curve25519 server + peer keypairs, 32-byte PSK,
//     randomized obfuscation params, port 51842/UDP, /24 server
//     and /32 peer carved out of 10.66.66.0/24.
//   - Subscription: 32-byte HMAC secret, default client id "default".
func generatePlan(opts InstallOptions, rng io.Reader) (*ProfileState, error) {
	if opts.Domain == "" {
		return nil, errors.New("Domain is required")
	}

	naiveUser, err := randomHex(rng, 8)
	if err != nil {
		return nil, fmt.Errorf("naive username: %w", err)
	}
	naivePass, err := randomHex(rng, 16)
	if err != nil {
		return nil, fmt.Errorf("naive password: %w", err)
	}

	secret := make([]byte, subscribe.SecretBytes)
	if _, err := io.ReadFull(rng, secret); err != nil {
		return nil, fmt.Errorf("subscription secret: %w", err)
	}
	clientID := defaultClientID
	token, err := subscribe.MakeToken(secret, clientID)
	if err != nil {
		return nil, fmt.Errorf("subscription token: %w", err)
	}

	naivePort := opts.NaivePort
	if naivePort == 0 {
		naivePort = defaultNaivePort
	}
	naiveSiteRoot := opts.NaiveSiteRoot
	if naiveSiteRoot == "" {
		naiveSiteRoot = naivetransport.DefaultSiteRoot
	}
	naiveSelfStealPort := opts.NaiveSelfStealPort
	if naiveSelfStealPort == 0 {
		naiveSelfStealPort = naivetransport.DefaultSelfStealPort
	}
	naiveSelfStealRoot := opts.NaiveSelfStealRoot
	if naiveSelfStealRoot == "" {
		naiveSelfStealRoot = naivetransport.DefaultSelfStealRoot
	}

	ps := &ProfileState{
		Profile: opts.Profile,
		Domain:  opts.Domain,
		Email:   opts.Email,
		Naive: &NaiveState{
			Username:      naiveUser,
			Password:      naivePass,
			ListenPort:    naivePort,
			SiteRoot:      naiveSiteRoot,
			SelfStealPort: naiveSelfStealPort,
			SelfStealRoot: naiveSelfStealRoot,
		},
		Subscription: &SubscriptionState{
			Secret:          base64.RawURLEncoding.EncodeToString(secret),
			DefaultClientID: clientID,
			Token:           token,
		},
	}

	if profileNeedsXray(opts.Profile) {
		uuid, err := generateUUIDFrom(rng)
		if err != nil {
			return nil, fmt.Errorf("xray uuid: %w", err)
		}
		keys, err := generateX25519From(rng)
		if err != nil {
			return nil, fmt.Errorf("xray x25519: %w", err)
		}
		shortID, err := randomHex(rng, 8)
		if err != nil {
			return nil, fmt.Errorf("xray short id: %w", err)
		}
		xrayPort := opts.XrayPort
		if xrayPort == 0 {
			xrayPort = xraytransport.DefaultListenPort
		}
		dest := opts.XrayDest
		if dest == "" {
			dest = fmt.Sprintf("127.0.0.1:%d", naiveSelfStealPort)
		}
		ps.Xray = &XrayState{
			Mode:       string(xraytransport.ModeVision),
			UUID:       uuid,
			PrivateKey: keys.Private,
			PublicKey:  keys.Public,
			ShortIDs:   []string{shortID},
			ListenPort: xrayPort,
			Dest:       dest,
		}
	}

	if profileNeedsHysteria2(opts.Profile) {
		hyPass, err := generateHysteria2PasswordFrom(rng)
		if err != nil {
			return nil, fmt.Errorf("hysteria2 password: %w", err)
		}
		hyPort := opts.Hysteria2Port
		if hyPort == 0 {
			hyPort = hysteria2transport.DefaultListenPort
		}
		// Default-style masquerade dials Caddy's selfsteal site on
		// the public Domain (not 127.0.0.1) so SNI matches Caddy's
		// site definition (`<Domain>:<SelfStealPort>`). Linux routes
		// `<own-public-IP>:<port>` back via loopback automatically,
		// so traffic stays on-host. Using 127.0.0.1 here would make
		// hy2 SNI the upstream as `127.0.0.1`, Caddy reject the TLS
		// handshake (`tls: internal error`), and active probes get a
		// bare 502 instead of the convincing selfsteal HTML — which
		// defeats the whole point of the masquerade.
		hyMasq := opts.Hysteria2MasqueradeURL
		if hyMasq == "" {
			hyMasq = fmt.Sprintf("https://%s:%d", opts.Domain, naiveSelfStealPort)
		}
		ps.Hysteria2 = &Hysteria2State{
			Password:      hyPass,
			ListenPort:    hyPort,
			MasqueradeURL: hyMasq,
		}
	}

	if profileNeedsAmneziaWG(opts.Profile) {
		awg, err := generateAmneziaWGStateFrom(opts, rng)
		if err != nil {
			return nil, fmt.Errorf("amneziawg: %w", err)
		}
		ps.AmneziaWG = awg
	}

	return ps, nil
}

// generateAmneziaWGStateFrom produces a fresh AmneziaWGState from the
// given rng. Two Curve25519 keypairs (server + single peer), one
// 32-byte PSK, a random obfuscation block, and the address/port
// triple are drawn here. CLI overrides on opts (listen-port,
// addresses, MTU, DNS) are applied; otherwise package defaults from
// internal/transport/amneziawg are used.
func generateAmneziaWGStateFrom(opts InstallOptions, rng io.Reader) (*AmneziaWGState, error) {
	server, err := amneziawgtransport.GenerateX25519FromReader(rng)
	if err != nil {
		return nil, fmt.Errorf("server keys: %w", err)
	}
	peer, err := amneziawgtransport.GenerateX25519FromReader(rng)
	if err != nil {
		return nil, fmt.Errorf("peer keys: %w", err)
	}
	psk, err := amneziawgtransport.GeneratePresharedKeyFromReader(rng)
	if err != nil {
		return nil, fmt.Errorf("preshared: %w", err)
	}
	obf, err := amneziawgtransport.GenerateObfuscationFromReader(rng)
	if err != nil {
		return nil, fmt.Errorf("obfuscation: %w", err)
	}
	listenPort := opts.AmneziaWGListenPort
	if listenPort == 0 {
		listenPort = amneziawgtransport.DefaultListenPort
	}
	serverAddr := opts.AmneziaWGServerAddress
	if serverAddr == "" {
		serverAddr = amneziawgtransport.DefaultServerAddress
	}
	peerAddr := opts.AmneziaWGPeerAddress
	if peerAddr == "" {
		peerAddr = amneziawgtransport.DefaultPeerAddress
	}
	mtu := opts.AmneziaWGMTU
	if mtu == 0 {
		mtu = amneziawgtransport.DefaultMTU
	}
	dns := opts.AmneziaWGDNS
	if dns == "" {
		dns = amneziawgtransport.DefaultDNS
	}
	return &AmneziaWGState{
		ServerPrivateKey: server.Private,
		ServerPublicKey:  server.Public,
		PeerPrivateKey:   peer.Private,
		PeerPublicKey:    peer.Public,
		PresharedKey:     psk,
		ListenPort:       listenPort,
		ServerAddress:    serverAddr,
		PeerAddress:      peerAddr,
		MTU:              mtu,
		DNS:              dns,
		Jc:               obf.Jc,
		Jmin:             obf.Jmin,
		Jmax:             obf.Jmax,
		S1:               obf.S1,
		S2:               obf.S2,
		H1:               obf.H1,
		H2:               obf.H2,
		H3:               obf.H3,
		H4:               obf.H4,
	}, nil
}

// generateHysteria2PasswordFrom mirrors hysteria2.GenerateAuthPassword
// (32 random bytes, base64.RawURL) but takes an injectable rng so
// tests can be deterministic. The implementation is duplicated (not
// delegated) to keep the orchestrator's plan reproducible from a
// single rng source.
func generateHysteria2PasswordFrom(rng io.Reader) (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rng, b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// profileHasTransport reports whether the named profile contains a
// transport with the given registry id. Returns false for unknown
// profiles. Used by the various profileNeedsX helpers below.
func profileHasTransport(profile, transportName string) bool {
	p, ok := profiles[profile]
	if !ok {
		return false
	}
	for _, t := range p.Transports {
		if t == transportName {
			return true
		}
	}
	return false
}

// profileNeedsXray reports whether the named profile contains the
// xray transport.
func profileNeedsXray(name string) bool { return profileHasTransport(name, "xray") }

// profileNeedsHysteria2 reports whether the named profile contains the
// hysteria2 transport.
func profileNeedsHysteria2(name string) bool { return profileHasTransport(name, "hysteria2") }

// profileNeedsAmneziaWG reports whether the named profile contains
// the amneziawg transport.
func profileNeedsAmneziaWG(name string) bool { return profileHasTransport(name, "amneziawg") }

const (
	defaultNaivePort = 8444
	defaultClientID  = "default"
)

// generateUUIDFrom mirrors xray.GenerateUUID but takes an injectable
// rng so tests can be deterministic. The implementation is duplicated
// (not delegated) to avoid leaking test seams into the public API of
// the xray package.
func generateUUIDFrom(rng io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rng, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func generateX25519From(rng io.Reader) (xraytransport.X25519Keys, error) {
	// Delegate via the xray package so we exercise the real
	// implementation; we just inject our rng.
	return xraytransport.GenerateX25519FromReader(rng)
}

func randomHex(rng io.Reader, n int) (string, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rng, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// secretBytes recovers the raw HMAC secret from the persisted form.
func (s *SubscriptionState) secretBytes() ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil subscription state")
	}
	if s.Secret == "" {
		return nil, errors.New("subscription secret is empty")
	}
	return base64.RawURLEncoding.DecodeString(s.Secret)
}

// defaultRand is the production randomness source. Variable for tests.
var defaultRand io.Reader = rand.Reader
