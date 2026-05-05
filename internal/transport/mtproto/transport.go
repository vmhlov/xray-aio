package mtproto

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
const Name = "mtproto"

type transportImpl struct {
	mgr *Manager
}

// New returns a fresh MTProto Transport ready to register.
func New() transport.Transport {
	return &transportImpl{mgr: NewManager()}
}

// Name returns the canonical id.
func (t *transportImpl) Name() string { return Name }

// Install reads MTProto-specific knobs from Options.Extra and
// delegates to [Manager.Install].
//
// Required Extra keys:
//
//	mtproto.secret        string   (32 hex chars)
//
// Optional Extra keys (with defaults):
//
//	mtproto.username      string   (DefaultUsername)
//	mtproto.listen_port   int      (DefaultListenPort)
//	mtproto.tls_domain    string   (DefaultTLSDomain)
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

// Probe runs a TCP-connect health check against the local listener.
// telemt speaks raw TLS-looking bytes on TCP, so a plain connect is
// enough to confirm the systemd unit is actually bound to its port.
// A deeper check (Fake-TLS ClientHello + secret handshake) would
// require dragging MTProto client logic into xray-aio's probe path —
// out of scope until Phase 3's health-probes work.
func (t *transportImpl) Probe(ctx context.Context) (transport.ProbeResult, error) {
	port := DefaultListenPort
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	start := time.Now()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return transport.ProbeResult{OK: false, Latency: latency, Notes: err.Error()}, nil
	}
	_ = conn.Close()
	return transport.ProbeResult{OK: true, Latency: latency, Notes: "tcp connect OK on " + addr}, nil
}

// Uninstall stops the unit and removes the unit + config tree.
func (t *transportImpl) Uninstall(ctx context.Context) error { return t.mgr.Uninstall(ctx) }

func configFromOptions(opts transport.Options) (Config, error) {
	if opts.Domain == "" {
		return Config{}, errors.New("Options.Domain is required")
	}
	cfg := Config{
		Domain:    opts.Domain,
		Username:  stringFrom(opts.Extra, "mtproto.username", ""),
		TLSDomain: stringFrom(opts.Extra, "mtproto.tls_domain", ""),
	}
	secret, err := requiredString(opts.Extra, "mtproto.secret")
	if err != nil {
		return Config{}, err
	}
	cfg.Secret = secret
	port, err := intFrom(opts.Extra, "mtproto.listen_port", DefaultListenPort)
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
	if !ok || s == "" {
		return "", fmt.Errorf("Extra[%q] must be a non-empty string", key)
	}
	return s, nil
}

// intFrom reads a numeric value from Extra. JSON round-trips turn
// numbers into float64, so we accept that shape too. Returns def
// when the key is absent.
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
