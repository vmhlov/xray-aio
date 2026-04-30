package hysteria2

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// URIInputs is the minimum the orchestrator hands to RenderURI.
// Mirrors the bits of Config the client cares about — server config
// has cert paths, masquerade etc. that don't belong in a public URI.
type URIInputs struct {
	Domain   string
	Port     int    // 0 → 443
	Password string // required
	SNI      string // empty → Domain
	Insecure bool   // self-signed certs only; LE deploys leave this false
	Tag      string // optional client-display label, e.g. "vpn.example.com (HY2)"
}

// RenderURI emits the canonical hysteria2:// URI documented at
// https://v2.hysteria.network/docs/developers/URI-Scheme/.
//
// Form: hysteria2://<password>@<host>:<port>/?sni=...&insecure=0#<tag>
//
// We use the `password@host` shape (the docs call it the "auth"
// component) because every modern client (NekoBox, sing-box, mihomo)
// expects exactly that. The Tag is appended as a URL fragment and
// percent-encoded so client UIs can show it as the connection name
// without breaking on spaces.
func RenderURI(in URIInputs) (string, error) {
	if strings.TrimSpace(in.Domain) == "" {
		return "", errors.New("hysteria2 URI: Domain is required")
	}
	if strings.TrimSpace(in.Password) == "" {
		return "", errors.New("hysteria2 URI: Password is required")
	}
	port := in.Port
	if port == 0 {
		port = DefaultListenPort
	}
	sni := in.SNI
	if sni == "" {
		sni = in.Domain
	}
	q := url.Values{}
	q.Set("sni", sni)
	if in.Insecure {
		q.Set("insecure", "1")
	} else {
		q.Set("insecure", "0")
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(in.Password),
		Host:     fmt.Sprintf("%s:%d", in.Domain, port),
		Path:     "/",
		RawQuery: q.Encode(),
	}
	if in.Tag != "" {
		u.Fragment = in.Tag
	}
	return u.String(), nil
}
