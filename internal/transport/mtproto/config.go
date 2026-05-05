package mtproto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DefaultListenPort is the TCP port telemt listens on out of the box.
// :443 is taken by REALITY, :8443/:8444 by Caddy selfsteal+naive.
// :8883 is the registered MQTT-over-TLS port — mutes suspicion in
// traffic captures and pairs with the "this is TLS" Fake-TLS story
// better than a random high port like :48443.
const DefaultListenPort = 8883

// DefaultTLSDomain is the SNI the client sends and whose real TLS
// fingerprint telemt emulates. Must be a real, reachable HTTPS
// site — telemt fetches its cert lengths on startup. www.microsoft.com
// is ubiquitous, has a well-behaved HTTPS endpoint, and is not
// blocked in any jurisdiction we target. Operators may override.
const DefaultTLSDomain = "www.microsoft.com"

// DefaultUsername is the identifier telemt uses inside [access.users].
// Not exposed to clients — it's just the map key that pairs with the
// user's secret. Kept stable across re-installs so re-rendering the
// config produces a byte-identical result when the secret has not
// rotated.
const DefaultUsername = "xray-aio"

// Config is the operator-facing knob set for one telemt install.
// Mirrors the TOML written by [Render] one-to-one; keep them in sync.
type Config struct {
	// Domain is the public hostname advertised in the tg:// URI. Not
	// used inside the server's own TOML — telemt does not need it —
	// but we keep it on the Config struct so the transport-layer
	// contract matches the hysteria2/naive packages (both of which
	// need Domain for TLS cert lookup, which telemt doesn't).
	Domain string

	// ListenPort is the TCP port to listen on. 0 → DefaultListenPort.
	ListenPort int

	// Secret is the 16-byte shared secret, hex-encoded (32 chars).
	// Required. [GenerateSecret] produces a fresh one.
	Secret string

	// Username is the [access.users] map key inside telemt's TOML.
	// Empty → DefaultUsername.
	Username string

	// TLSDomain is the SNI the client sends and whose TLS fingerprint
	// telemt emulates. Empty → DefaultTLSDomain.
	TLSDomain string
}

// Validate returns nil when cfg can be rendered. Pure data-shape
// checks; nothing that would touch the filesystem or hit the network.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Domain) == "" {
		return errors.New("mtproto: Domain is required")
	}
	if err := validateSecret(c.Secret); err != nil {
		return err
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return fmt.Errorf("mtproto: ListenPort %d out of range", c.ListenPort)
	}
	if strings.ContainsAny(c.Username, " \t\r\n\"'") {
		return fmt.Errorf("mtproto: Username %q contains whitespace or quote", c.Username)
	}
	if strings.ContainsAny(c.TLSDomain, " \t\r\n\"'") {
		return fmt.Errorf("mtproto: TLSDomain %q contains whitespace or quote", c.TLSDomain)
	}
	return nil
}

// validateSecret requires a 32-char lowercase-or-uppercase hex string.
// Empty is not valid — [GenerateSecret] or an explicit operator value
// must populate it before Install.
func validateSecret(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("mtproto: Secret is required (32 hex chars)")
	}
	if len(s) != 32 {
		return fmt.Errorf("mtproto: Secret must be 32 hex chars, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("mtproto: Secret is not valid hex: %w", err)
	}
	return nil
}

// Render emits the TOML config telemt expects. Keep the output
// stable: [config_test.go] golden-tests against the exact bytes.
//
// We hand-roll the TOML (no github.com/BurntSushi/toml dep) for the
// same reason hysteria2's Render hand-rolls YAML: the schema is
// small, templating is clearer than dragging a generic encoder into
// the production dep tree, and the golden-test catches any drift.
//
// telemt's TOML sections we care about:
//
//	[general]               use_middle_proxy=true, log_level=normal
//	[general.modes]         tls=true only
//	[general.links]         show="*" so the API returns URIs for all users
//	[server]                port=<listen>
//	[[server.listeners]]    ip="0.0.0.0"
//	[server.api]            enabled, localhost-only
//	[censorship]            tls_domain, mask=true, tls_emulation=true
//	[access.users]          <username> = "<secret>"
//
// Everything else (prometheus, whitelisting, proxy_protocol, …) is
// left at telemt's own defaults. Operators who need those can drop
// an override file under /etc/xray-aio/mtproto/conf.d/ — out of
// scope for Phase 2.3.
func Render(cfg Config) (string, error) {
	if err := cfg.Validate(); err != nil {
		return "", err
	}
	port := cfg.ListenPort
	if port == 0 {
		port = DefaultListenPort
	}
	tlsDomain := cfg.TLSDomain
	if tlsDomain == "" {
		tlsDomain = DefaultTLSDomain
	}
	username := cfg.Username
	if username == "" {
		username = DefaultUsername
	}
	var b strings.Builder
	b.WriteString("# Rendered by xray-aio. Do not edit by hand.\n")
	b.WriteString("# See https://github.com/telemt/telemt for upstream schema.\n\n")
	b.WriteString("[general]\n")
	b.WriteString("use_middle_proxy = true\n")
	b.WriteString("log_level = \"normal\"\n\n")
	b.WriteString("[general.modes]\n")
	b.WriteString("classic = false\n")
	b.WriteString("secure = false\n")
	b.WriteString("tls = true\n\n")
	b.WriteString("[general.links]\n")
	b.WriteString("show = \"*\"\n\n")
	b.WriteString("[server]\n")
	fmt.Fprintf(&b, "port = %d\n\n", port)
	b.WriteString("[[server.listeners]]\n")
	b.WriteString("ip = \"0.0.0.0\"\n\n")
	b.WriteString("[server.api]\n")
	b.WriteString("enabled = true\n")
	b.WriteString("listen = \"127.0.0.1:9091\"\n")
	b.WriteString("whitelist = [\"127.0.0.1/32\", \"::1/128\"]\n\n")
	b.WriteString("[censorship]\n")
	fmt.Fprintf(&b, "tls_domain = %q\n", tlsDomain)
	b.WriteString("mask = true\n")
	b.WriteString("tls_emulation = true\n\n")
	b.WriteString("[access.users]\n")
	fmt.Fprintf(&b, "%s = %q\n", username, strings.ToLower(cfg.Secret))
	return b.String(), nil
}
