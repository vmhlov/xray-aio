package subscribe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SecretBytes is the size of the HMAC key used to sign subscription
// tokens. 32 bytes (256 bits) is comfortably above the SHA-256
// security boundary and is what crypto/rand returns most cleanly.
const SecretBytes = 32

// tagBytes is the HMAC truncation length emitted into the token. 16
// bytes is plenty (collision resistance > 2^64 forgeries; preimage
// resistance > 2^128) while keeping the URL slug short enough to fit
// in QR codes without errors.
const tagBytes = 16

// GenerateSecret returns a fresh HMAC key for token signing. Callers
// persist it in state.json so subsequent process restarts can verify
// previously-issued tokens.
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, SecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return secret, nil
}

// MakeToken returns a URL-safe token of the form "<id>.<tag>" where
//   - id is the caller-supplied identifier (typically a profile name
//     like "default" or a per-client UUID), URL-safe-base64-encoded;
//   - tag is the first [tagBytes] of HMAC-SHA256(secret, id).
//
// The id is encoded so callers can pass arbitrary strings (including
// UUIDs and emails) without having to escape '.' or '/' themselves.
func MakeToken(secret []byte, id string) (string, error) {
	if len(secret) < SecretBytes/2 {
		return "", fmt.Errorf("secret too short: %d bytes (want %d)", len(secret), SecretBytes)
	}
	if id == "" {
		return "", errors.New("id is empty")
	}
	encID := base64.RawURLEncoding.EncodeToString([]byte(id))
	tag := hmacTag(secret, encID)
	return encID + "." + base64.RawURLEncoding.EncodeToString(tag), nil
}

// VerifyToken returns the original id encoded into the token if the
// HMAC matches. Constant-time comparison guards against timing
// oracles. Errors do not leak whether the failure was structural
// (malformed token) or cryptographic (bad tag).
func VerifyToken(secret []byte, token string) (string, error) {
	if len(secret) < SecretBytes/2 {
		return "", errors.New("secret too short")
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("invalid token")
	}
	gotTag, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid token")
	}
	wantTag := hmacTag(secret, parts[0])
	if !hmac.Equal(gotTag, wantTag) {
		return "", errors.New("invalid token")
	}
	id, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid token")
	}
	return string(id), nil
}

// hmacTag computes a truncated HMAC-SHA256 over data and returns
// [tagBytes] of the result.
func hmacTag(secret []byte, data string) []byte {
	h := hmac.New(sha256.New, secret)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)[:tagBytes]
}
