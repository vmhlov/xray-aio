package mtproto

import (
	"crypto/rand"
	"encoding/hex"
)

// GenerateSecret returns a fresh 16-byte random secret encoded as
// 32 lowercase hex characters. This is the canonical MTProto proxy
// secret format — 16 bytes is exactly what Telegram's client-side
// key-derivation expects.
//
// The returned string is suitable as both [Config.Secret] (server
// side) and as the payload portion of the Fake-TLS "EE"-prefixed
// secret in the tg://proxy URI (see [RenderURI]).
func GenerateSecret() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
