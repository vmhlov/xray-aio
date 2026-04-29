package orchestrator

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/vmhlov/xray-aio/internal/subscribe"
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
	dest := opts.XrayDest
	if dest == "" {
		dest = defaultXrayDest
	}

	return &ProfileState{
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
			Username:   naiveUser,
			Password:   naivePass,
			ListenPort: naivePort,
			SiteRoot:   naiveSiteRoot,
		},
		Subscription: &SubscriptionState{
			Secret:          base64.RawURLEncoding.EncodeToString(secret),
			DefaultClientID: clientID,
			Token:           token,
		},
	}, nil
}

const (
	defaultNaivePort = 8444
	defaultXrayDest  = "127.0.0.1:8443"
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
