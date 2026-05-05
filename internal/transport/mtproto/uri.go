package mtproto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// URIInputs is the minimum the orchestrator hands to [RenderURI].
// Mirrors the public-facing knobs from Config; server-only bits
// (username, API listen, log level) are absent on purpose.
type URIInputs struct {
	// Domain is the public hostname clients dial (the operator's real
	// TLS domain — NOT the Fake-TLS decoy).
	Domain string

	// Port is the public TCP port. 0 → DefaultListenPort.
	Port int

	// Secret is the 16-byte secret encoded as 32 hex chars. Required.
	Secret string

	// TLSDomain is the Fake-TLS decoy domain embedded in the EE-prefix
	// secret. Empty → DefaultTLSDomain.
	TLSDomain string
}

// RenderURI emits the canonical MTProto Fake-TLS (EE-prefix) URI
// understood by modern Telegram clients. Form:
//
//	tg://proxy?server=<host>&port=<port>&secret=ee<32hex><tls_domain_hex>
//
// The EE-prefix secret format is Telegram's wire convention for
// signalling Fake-TLS mode to the client: leading byte 0xEE tells the
// client "use Fake-TLS, tls_domain follows after the 16-byte random
// secret, in raw bytes". Everything is hex-encoded for URI safety.
//
// See also:
//   - https://core.telegram.org/api/obfuscation#mtproto-proxy
//   - https://github.com/telemt/telemt (server side)
//
// The Telegram `https://t.me/proxy?...` variant is emitted by
// [RenderHTTPSURI] — same query string, different scheme.
func RenderURI(in URIInputs) (string, error) {
	return renderURI("tg", in)
}

// RenderHTTPSURI emits the https://t.me/proxy?... variant that is
// safe to ship in an HTML landing page (operating systems resolve
// the t.me hostname themselves and hand off to the Telegram client).
func RenderHTTPSURI(in URIInputs) (string, error) {
	return renderURI("https", in)
}

func renderURI(scheme string, in URIInputs) (string, error) {
	if strings.TrimSpace(in.Domain) == "" {
		return "", errors.New("mtproto URI: Domain is required")
	}
	if err := validateSecret(in.Secret); err != nil {
		return "", fmt.Errorf("mtproto URI: %w", err)
	}
	port := in.Port
	if port == 0 {
		port = DefaultListenPort
	}
	tlsDomain := in.TLSDomain
	if tlsDomain == "" {
		tlsDomain = DefaultTLSDomain
	}
	// EE-prefix = "ee" || hex(secret_bytes) || hex(tls_domain_utf8).
	// All three are already hex-safe, so a plain concat suffices.
	eeSecret := "ee" + strings.ToLower(in.Secret) + hex.EncodeToString([]byte(tlsDomain))
	q := url.Values{}
	q.Set("server", in.Domain)
	q.Set("port", fmt.Sprintf("%d", port))
	q.Set("secret", eeSecret)
	switch scheme {
	case "tg":
		// tg://proxy?... — keep the opaque form so url.URL does not
		// inject an empty authority (`//`) before `proxy`.
		return "tg://proxy?" + q.Encode(), nil
	case "https":
		u := url.URL{Scheme: "https", Host: "t.me", Path: "/proxy", RawQuery: q.Encode()}
		return u.String(), nil
	default:
		return "", fmt.Errorf("mtproto URI: unsupported scheme %q", scheme)
	}
}
