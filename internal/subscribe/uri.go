package subscribe

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESSConfig is the per-client view of a VLESS REALITY listener,
// mirroring what the orchestrator persisted in state.json plus the
// client's own UUID.
type VLESSConfig struct {
	UUID        string // VLESS client id
	Domain      string // SNI / Host
	Port        int    // public port (typically 443)
	PublicKey   string // REALITY x25519 public key (base64 RawURL)
	ShortID     string // hex; one of the server's accepted shortIds
	Mode        string // "vision" or "xhttp"
	XHTTPPath   string // only used in xhttp mode
	Label       string // pretty name shown in clients (URI fragment)
	Fingerprint string // browser fingerprint, default "chrome"
}

// VLESSURI returns the vless:// URL accepted by NekoBox / Hiddify /
// Streisand / Happ. Format is the de-facto standard documented in
// XTLS/Xray-core's README and tested against multiple clients.
func VLESSURI(c VLESSConfig) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("security", "reality")
	q.Set("sni", c.Domain)
	q.Set("pbk", c.PublicKey)
	q.Set("sid", c.ShortID)
	if c.Fingerprint == "" {
		q.Set("fp", "chrome")
	} else {
		q.Set("fp", c.Fingerprint)
	}
	switch c.Mode {
	case "vision":
		q.Set("type", "tcp")
		q.Set("flow", "xtls-rprx-vision")
	case "xhttp":
		q.Set("type", "xhttp")
		q.Set("path", c.XHTTPPath)
		q.Set("mode", "auto")
	default:
		return "", fmt.Errorf("unknown mode %q", c.Mode)
	}
	host := c.Domain + ":" + strconv.Itoa(c.Port)
	out := "vless://" + url.PathEscape(c.UUID) + "@" + host + "?" + q.Encode()
	if c.Label != "" {
		out += "#" + url.PathEscape(c.Label)
	}
	return out, nil
}

func (c VLESSConfig) validate() error {
	if c.UUID == "" {
		return errors.New("UUID is empty")
	}
	if c.Domain == "" {
		return errors.New("Domain is empty")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("Port %d out of range", c.Port)
	}
	if c.PublicKey == "" {
		return errors.New("PublicKey is empty")
	}
	if c.ShortID == "" {
		return errors.New("ShortID is empty")
	}
	if c.Mode == "xhttp" {
		if !strings.HasPrefix(c.XHTTPPath, "/") {
			return fmt.Errorf("XHTTPPath must start with '/', got %q", c.XHTTPPath)
		}
	}
	return nil
}

// NaiveConfig is the per-client view of a NaïveProxy listener.
type NaiveConfig struct {
	Username string
	Password string
	Domain   string
	Port     int
	Label    string // pretty name shown in clients
}

// NaiveURI returns a "naive+https://" URL. Matches the format used by
// the upstream naive client and the NekoBox importer. Padding=true is
// appended because the server is QUIC-capable and clients benefit
// from the random padding.
func NaiveURI(c NaiveConfig) (string, error) {
	if c.Username == "" || c.Password == "" {
		return "", errors.New("Username and Password are required")
	}
	if c.Domain == "" {
		return "", errors.New("Domain is empty")
	}
	if c.Port <= 0 || c.Port > 65535 {
		return "", fmt.Errorf("Port %d out of range", c.Port)
	}
	userInfo := url.QueryEscape(c.Username) + ":" + url.QueryEscape(c.Password)
	host := c.Domain + ":" + strconv.Itoa(c.Port)
	out := "naive+https://" + userInfo + "@" + host + "?padding=true"
	if c.Label != "" {
		out += "#" + url.PathEscape(c.Label)
	}
	return out, nil
}
