package hysteria2

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateAuthPassword returns a 32-byte random password encoded as
// base64 raw-url. ~43 chars, indistinguishable from random by an
// observer. Suitable as a Hysteria 2 `auth.password` value.
func GenerateAuthPassword() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
