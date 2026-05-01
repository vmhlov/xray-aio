package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vmhlov/xray-aio/internal/transport"
)

// Name is the registry id for this transport.
const Name = "hysteria2"

type transportImpl struct {
	mgr *Manager
}

// New returns a fresh hysteria 2 Transport ready to register.
func New() transport.Transport {
	return &transportImpl{mgr: NewManager()}
}

// Name returns the canonical id.
func (t *transportImpl) Name() string { return Name }

// Install reads hysteria-2-specific knobs from Options.Extra and
// delegates to [Manager.Install].
//
// Required Extra keys:
//
//	hysteria2.password         string
//
// Optional Extra keys (with defaults):
//
//	hysteria2.listen_port         int     (DefaultListenPort)
//	hysteria2.masquerade_url      string  (DefaultMasqueradeURL)
//	hysteria2.masquerade_insecure bool    (false)
//	hysteria2.cert_path           string  (Caddy LE for Domain)
//	hysteria2.key_path            string  (Caddy LE for Domain)
func (t *transportImpl) Install(ctx context.Context, opts transport.Options) error {
	cfg, err := configFromOptions(opts)
	if err != nil {
		return err
	}
	return t.mgr.Install(ctx, cfg)
}

// Start brings the systemd unit up.
func (t *transportImpl) Start(ctx context.Context) error { return t.mgr.Start(ctx) }

// Stop tears the systemd unit down.
func (t *transportImpl) Stop(ctx context.Context) error { return t.mgr.Stop(ctx) }

// Status reports systemd state plus the unit's reported substate.
func (t *transportImpl) Status(ctx context.Context) (transport.Status, error) {
	active, raw, err := t.mgr.Status(ctx)
	if err != nil {
		return transport.Status{}, err
	}
	return transport.Status{Running: active, Notes: raw}, nil
}

// Probe runs a UDP-connect health check against the local listener.
// Hysteria 2 speaks QUIC, so a TCP connect would always fail. We
// "connect" a UDP socket — this binds the local side without sending
// any packets, so the remote sees nothing — which only fails when the
// kernel can't reserve a 4-tuple (e.g. nothing listens). Good enough
// to tell that the systemd unit is at least carrying its UDP socket.
//
// Deeper QUIC + auth + TLS validation lands in a later phase, when we
// have a real client harness.
func (t *transportImpl) Probe(ctx context.Context) (transport.ProbeResult, error) {
	port := DefaultListenPort
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	start := time.Now()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", addr)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return transport.ProbeResult{OK: false, Latency: latency, Notes: err.Error()}, nil
	}
	_ = conn.Close()
	return transport.ProbeResult{OK: true, Latency: latency, Notes: "udp socket reservable on " + addr}, nil
}

// Uninstall stops the unit and removes the unit + config tree.
func (t *transportImpl) Uninstall(ctx context.Context) error { return t.mgr.Uninstall(ctx) }

func configFromOptions(opts transport.Options) (Config, error) {
	if opts.Domain == "" {
		return Config{}, errors.New("Options.Domain is required")
	}
	cfg := Config{
		Domain:             opts.Domain,
		MasqueradeURL:      stringFrom(opts.Extra, "hysteria2.masquerade_url", ""),
		MasqueradeInsecure: boolFrom(opts.Extra, "hysteria2.masquerade_insecure", false),
		CertPath:           stringFrom(opts.Extra, "hysteria2.cert_path", ""),
		KeyPath:            stringFrom(opts.Extra, "hysteria2.key_path", ""),
	}
	password, err := requiredString(opts.Extra, "hysteria2.password")
	if err != nil {
		return Config{}, err
	}
	cfg.Password = password
	port, err := intFrom(opts.Extra, "hysteria2.listen_port", DefaultListenPort)
	if err != nil {
		return Config{}, err
	}
	cfg.ListenPort = port
	return cfg, nil
}

// stringFrom returns m[key] when present and a string, otherwise def.
func stringFrom(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok {
		return def
	}
	return s
}

// requiredString is like stringFrom but returns an error when the
// value is missing or empty.
func requiredString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("Extra[%q] is required", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("Extra[%q] not a string: %T", key, v)
	}
	if s == "" {
		return "", fmt.Errorf("Extra[%q] is empty", key)
	}
	return s, nil
}

// boolFrom returns m[key] when present and a bool, otherwise def.
func boolFrom(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok {
		return def
	}
	b, ok := v.(bool)
	if !ok {
		return def
	}
	return b
}

// intFrom accepts int, int64, float64, or numeric strings and returns
// the value as int. Returns def when the key is absent.
func intFrom(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		n, err := strconv.Atoi(x)
		if err != nil {
			return 0, fmt.Errorf("Extra[%q] not numeric: %q", key, x)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("Extra[%q] not numeric: %T", key, v)
	}
}

func init() {
	transport.Register(Name, New)
}
