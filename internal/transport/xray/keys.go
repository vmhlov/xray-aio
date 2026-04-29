package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// GenerateUUID returns an RFC 4122 v4 UUID. It exists so we don't have
// to shell out to `xray uuid` during install.
func GenerateUUID() (string, error) {
	return generateUUID(rand.Reader)
}

func generateUUID(r io.Reader) (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	// RFC 4122 § 4.4: set version (4) and variant (10).
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// X25519Keys is a REALITY keypair encoded the way Xray expects: URL-safe
// base64 (no padding) for both halves.
type X25519Keys struct {
	Private string
	Public  string
}

// GenerateX25519 returns a fresh REALITY keypair, mirroring `xray x25519`.
// Output uses base64.RawURLEncoding (no padding) which Xray-core 1.8+
// accepts in `realitySettings.privateKey`.
func GenerateX25519() (X25519Keys, error) {
	return generateX25519(rand.Reader)
}

// GenerateX25519FromReader is the same as [GenerateX25519] but takes an
// injectable randomness source. The orchestrator uses it to drive
// deterministic tests; production callers should prefer
// [GenerateX25519].
func GenerateX25519FromReader(r io.Reader) (X25519Keys, error) {
	return generateX25519(r)
}

func generateX25519(r io.Reader) (X25519Keys, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(r)
	if err != nil {
		return X25519Keys{}, fmt.Errorf("x25519: %w", err)
	}
	enc := base64.RawURLEncoding
	return X25519Keys{
		Private: enc.EncodeToString(priv.Bytes()),
		Public:  enc.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// GenerateShortID returns nBytes worth of hex (so a 16-char string for
// nBytes=8). REALITY accepts 1..16-byte short ids; 8 is the typical
// pick.
func GenerateShortID(nBytes int) (string, error) {
	return generateShortID(rand.Reader, nBytes)
}

func generateShortID(r io.Reader, nBytes int) (string, error) {
	if nBytes < 1 || nBytes > 16 {
		return "", fmt.Errorf("ShortID byte length %d out of range [1,16]", nBytes)
	}
	buf := make([]byte, nBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// validateShortID checks that s is 1..16 bytes of lowercase hex (the
// form REALITY's protocol-level matcher recognizes).
func validateShortID(s string) error {
	if s == "" {
		return errors.New("empty")
	}
	if len(s) > 32 || len(s)%2 != 0 {
		return fmt.Errorf("length %d invalid (must be even, ≤ 32)", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("not hex: %w", err)
	}
	if strings.ToLower(s) != s {
		return fmt.Errorf("must be lowercase: %q", s)
	}
	return nil
}

// looksLikeUUID is a cheap structural check; it does not enforce that
// version/variant bits are correct, only that the surface shape is
// 8-4-4-4-12 hex.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexLower(byte(c)) {
				return false
			}
		}
	}
	return true
}

func isHexLower(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}
