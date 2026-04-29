package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Mode selects the stealth stack riding on top of REALITY.
type Mode string

const (
	// ModeVision is REALITY + TCP + xtls-rprx-vision flow. Most
	// battle-tested combination as of 2026.
	ModeVision Mode = "vision"

	// ModeXHTTP is REALITY + XHTTP (HTTP/2 framing). Better at
	// surviving ML-based traffic-shape classifiers; slightly newer
	// in the field.
	ModeXHTTP Mode = "xhttp"
)

// Config drives the Xray JSON config render. All knobs that have
// security implications live here as named fields; everything else is
// hard-coded so an operator can't misconfigure the stealth properties
// by accident.
type Config struct {
	// Domain is the public FQDN — used as REALITY serverName so
	// fingerprint matches what Caddy is serving for selfsteal.
	Domain string

	// ListenPort is where the inbound VLESS listener binds. Defaults
	// to 443 (you almost never want anything else).
	ListenPort int

	// Dest is the upstream that REALITY borrows the TLS handshake
	// from when it sees non-VLESS traffic. For selfsteal that is the
	// local Caddy serving Domain on a different port (e.g.
	// 127.0.0.1:8443).
	Dest string

	// UUID is the VLESS client identifier.
	UUID string

	// PrivateKey / PublicKey is the REALITY x25519 keypair. Only
	// PrivateKey ends up in the server config; PublicKey is used by
	// the client subscription (Phase 1.5).
	PrivateKey string
	PublicKey  string

	// ShortIDs is the list of 1..16-byte hex blobs the server
	// accepts. At least one entry is required.
	ShortIDs []string

	// Mode selects [ModeVision] or [ModeXHTTP]. Defaults to Vision.
	Mode Mode

	// XHTTPPath is the URL path used in [ModeXHTTP]. Defaults to
	// "/" + 8 random hex chars derived from the first ShortID — but
	// callers should pass an explicit value for stability.
	XHTTPPath string
}

// DefaultListenPort is where REALITY listens by default.
const DefaultListenPort = 443

// Render returns the Xray JSON config for c.
//
// The caller is expected to have populated UUID, PrivateKey, PublicKey
// and at least one ShortID via [GenerateUUID], [GenerateX25519] and
// [GenerateShortID]. Render itself does not generate secrets — that
// makes the function deterministic and trivial to test.
func Render(c Config) (string, error) {
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return "", err
	}

	streamSettings := buildStreamSettings(c)

	clients := []map[string]any{{"id": c.UUID}}
	if c.Mode == ModeVision {
		clients[0]["flow"] = "xtls-rprx-vision"
	}

	cfg := map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
			"dnsLog":   false,
		},
		"inbounds": []map[string]any{
			{
				"tag":      "vless-reality",
				"listen":   "0.0.0.0",
				"port":     c.ListenPort,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    clients,
					"decryption": "none",
				},
				"streamSettings": streamSettings,
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []map[string]any{
			{"protocol": "freedom", "tag": "direct"},
			{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules":          []any{},
		},
	}

	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return string(body) + "\n", nil
}

func buildStreamSettings(c Config) map[string]any {
	reality := map[string]any{
		"show":        false,
		"dest":        c.Dest,
		"xver":        0,
		"serverNames": []string{c.Domain},
		"privateKey":  c.PrivateKey,
		"shortIds":    c.ShortIDs,
	}

	switch c.Mode {
	case ModeXHTTP:
		return map[string]any{
			"network":         "xhttp",
			"security":        "reality",
			"realitySettings": reality,
			"xhttpSettings": map[string]any{
				"path": c.XHTTPPath,
				"mode": "auto",
			},
		}
	default: // ModeVision
		return map[string]any{
			"network":         "tcp",
			"security":        "reality",
			"realitySettings": reality,
		}
	}
}

func (c *Config) applyDefaults() {
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
	if c.Mode == "" {
		c.Mode = ModeVision
	}
	if c.Mode == ModeXHTTP && c.XHTTPPath == "" && len(c.ShortIDs) > 0 {
		c.XHTTPPath = "/" + c.ShortIDs[0]
	}
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Domain) == "" {
		return errors.New("Domain is required")
	}
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		return fmt.Errorf("ListenPort %d out of range", c.ListenPort)
	}
	if c.Dest == "" {
		return errors.New("Dest is required (e.g. 127.0.0.1:8443)")
	}
	if !strings.Contains(c.Dest, ":") {
		return fmt.Errorf("Dest must be host:port, got %q", c.Dest)
	}
	if !looksLikeUUID(c.UUID) {
		return fmt.Errorf("UUID malformed: %q", c.UUID)
	}
	if c.PrivateKey == "" || c.PublicKey == "" {
		return errors.New("PrivateKey and PublicKey are required")
	}
	if len(c.ShortIDs) == 0 {
		return errors.New("at least one ShortID is required")
	}
	for i, s := range c.ShortIDs {
		if err := validateShortID(s); err != nil {
			return fmt.Errorf("ShortIDs[%d]: %w", i, err)
		}
	}
	switch c.Mode {
	case ModeVision, ModeXHTTP:
	default:
		return fmt.Errorf("Mode %q unknown", c.Mode)
	}
	if c.Mode == ModeXHTTP {
		if c.XHTTPPath == "" {
			return errors.New("XHTTPPath is required in ModeXHTTP")
		}
		if !strings.HasPrefix(c.XHTTPPath, "/") {
			return fmt.Errorf("XHTTPPath must start with /, got %q", c.XHTTPPath)
		}
	}
	return nil
}
