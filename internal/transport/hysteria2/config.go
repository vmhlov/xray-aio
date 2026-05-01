package hysteria2

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// DefaultListenPort is the UDP port Hysteria 2 listens on out of the
// box. Mirrors upstream's default and pairs naturally with the TCP/443
// REALITY listener — different L4 protocols, no kernel-level conflict.
const DefaultListenPort = 443

// DefaultMasqueradeURL is the loopback selfsteal site that our naive
// transport already serves. Picking the same URL keeps the public TLS
// fingerprint the REALITY landing site advertises consistent with the
// fallback hysteria 2 returns when a probe misbehaves.
const DefaultMasqueradeURL = "https://127.0.0.1:8443"

// caddyACMEDir is the immutable path Caddy uses for the LE production
// directory under XDG_DATA_HOME. We pin it instead of probing the
// filesystem because the transport package must be deterministic for
// tests, and Caddy's ACME directory layout is documented and stable.
const caddyACMEDir = "/var/lib/caddy/caddy/certificates/acme-v02.api.letsencrypt.org-directory"

// Config is the operator-facing knob set for one hysteria 2 install.
// Mirrors the YAML structure in [Render] one-to-one — keep them in
// sync.
type Config struct {
	// Domain is the public hostname clients dial. Used to derive the
	// default cert/key paths under Caddy's storage when the operator
	// has not overridden CertPath/KeyPath.
	Domain string

	// ListenPort is the UDP port to listen on. 0 → DefaultListenPort.
	ListenPort int

	// Password is the shared secret. Required.
	Password string

	// MasqueradeURL is the upstream the server proxies to when an
	// authentication failure or unsolicited HTTPS request arrives.
	// Empty → DefaultMasqueradeURL.
	MasqueradeURL string

	// CertPath / KeyPath let the operator override the default Caddy
	// LE path. Useful for an externally-managed cert. Both empty →
	// derive from Domain.
	CertPath string
	KeyPath  string

	// MasqueradeInsecure tells the masquerade.proxy upstream dialer
	// to skip TLS certificate verification.
	//
	// When the masquerade upstream is the loopback Caddy selfsteal
	// site (https://127.0.0.1:<SelfStealPort>), hy2 will SNI the
	// upstream with the literal "127.0.0.1" — but Caddy's site
	// definition is `<domain>:<SelfStealPort>` and rejects any other
	// SNI, so the TLS handshake fails with `internal error` and
	// active probes get a bare 502 instead of the convincing
	// selfsteal HTML.
	//
	// Setting this true skips that verification on the loopback hop
	// only — the real client→server hy2 leg is still cert-checked
	// against Domain. Hysteria 2 supports this via
	// `masquerade.proxy.insecure: true` (since v2.6.0).
	//
	// The orchestrator turns this on automatically whenever the
	// masquerade URL is the default-style loopback. An operator who
	// pins a public masquerade gets the safer default of false.
	MasqueradeInsecure bool
}

// Validate returns nil when cfg can be rendered. Pure data-shape
// checks; nothing that would touch the filesystem or hit the network.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Domain) == "" {
		return errors.New("hysteria2: Domain is required")
	}
	if strings.TrimSpace(c.Password) == "" {
		return errors.New("hysteria2: Password is required")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("hysteria2: ListenPort %d out of range", c.ListenPort)
	}
	return nil
}

// CertPaths returns (certPath, keyPath) with Caddy-LE defaults applied.
func (c Config) CertPaths() (cert, key string) {
	cert = c.CertPath
	if cert == "" {
		cert = filepath.Join(caddyACMEDir, c.Domain, c.Domain+".crt")
	}
	key = c.KeyPath
	if key == "" {
		key = filepath.Join(caddyACMEDir, c.Domain, c.Domain+".key")
	}
	return cert, key
}

// Render emits the YAML config Hysteria 2 expects. Keep the output
// stable: [config_test.go] golden-tests against the exact bytes.
//
// We hand-roll the YAML (no gopkg.in/yaml.v3 dep) because the schema
// is small enough that templating is clearer than wrestling with
// indent rules in a generic encoder, and we avoid pulling a 2k-LoC
// dependency for a few dozen lines of output.
func Render(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	port := cfg.ListenPort
	if port == 0 {
		port = DefaultListenPort
	}
	masq := cfg.MasqueradeURL
	if masq == "" {
		masq = DefaultMasqueradeURL
	}
	certPath, keyPath := cfg.CertPaths()

	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by xray-aio. Do not edit by hand — re-run `xray-aio install`.\n")
	fmt.Fprintf(&b, "listen: :%d\n\n", port)
	b.WriteString("tls:\n")
	fmt.Fprintf(&b, "  cert: %s\n", certPath)
	fmt.Fprintf(&b, "  key: %s\n\n", keyPath)
	b.WriteString("auth:\n")
	b.WriteString("  type: password\n")
	fmt.Fprintf(&b, "  password: %s\n\n", cfg.Password)
	b.WriteString("masquerade:\n")
	b.WriteString("  type: proxy\n")
	b.WriteString("  proxy:\n")
	fmt.Fprintf(&b, "    url: %s\n", masq)
	b.WriteString("    rewriteHost: true\n")
	if cfg.MasqueradeInsecure {
		b.WriteString("    insecure: true\n")
	}
	return b.String(), nil
}
