package orchestrator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/vmhlov/xray-aio/internal/subscribe"
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
//   - Subscription: 32-byte HMAC secret, default client id "default".
func generatePlan(opts InstallOptions, rng io.Reader) (*ProfileState, error) {
	if opts.Domain == "" {
		return nil, errors.New("Domain is required")
	}

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

	xrayPort := opts.XrayPort
	if xrayPort == 0 {
		xrayPort = xraytransport.DefaultListenPort
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
	dest := opts.XrayDest
	if dest == "" {
		dest = fmt.Sprintf("127.0.0.1:%d", naiveSelfStealPort)
	}

	ps := &ProfileState{
		Profile: opts.Profile,
		Domain:  opts.Domain,
		Email:   opts.Email,
		Xray: &XrayState{
			Mode:       string(xraytransport.ModeVision),
			UUID:       uuid,
			PrivateKey: keys.Private,
			PublicKey:  keys.Public,
			ShortIDs:   []string{shortID},
			ListenPort: xrayPort,
			Dest:       dest,
		},
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

	return ps, nil
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

// profileNeedsHysteria2 reports whether the named profile contains the
// hysteria2 transport. Lookup goes through the package's profile
// registry so a future profile that adds hy2 picks up the right
// generation behaviour automatically.
func profileNeedsHysteria2(name string) bool {
	p, ok := profiles[name]
	if !ok {
		return false
	}
	for _, t := range p.Transports {
		if t == "hysteria2" {
			return true
		}
	}
	return false
}

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
