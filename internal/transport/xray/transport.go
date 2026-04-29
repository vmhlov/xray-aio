package xray

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
const Name = "xray"

// transportImpl bridges [Manager] to [transport.Transport]. Created by
// the registry factory.
type transportImpl struct {
	mgr *Manager
}

// New returns a fresh xray Transport ready to register.
func New() transport.Transport {
	return &transportImpl{mgr: NewManager()}
}

// Name returns the canonical id.
func (t *transportImpl) Name() string { return Name }

// Install reads xray-specific knobs from Options.Extra and delegates
// to [Manager.Install].
//
// Required Extra keys:
//
//	xray.uuid           string
//	xray.private_key    string  (raw url base64, see GenerateX25519)
//	xray.public_key     string  (raw url base64)
//	xray.short_ids      []string
//
// Optional Extra keys (with defaults):
//
//	xray.dest           string  ("127.0.0.1:8443")
//	xray.listen_port    int     (443)
//	xray.mode           string  ("vision" | "xhttp"; default "vision")
//	xray.xhttp_path     string  (derived from first short_id when empty)
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

// Status reports systemd state plus the listening PID, when known.
func (t *transportImpl) Status(ctx context.Context) (transport.Status, error) {
	active, raw, err := t.mgr.Status(ctx)
	if err != nil {
		return transport.Status{}, err
	}
	return transport.Status{Running: active, Notes: raw}, nil
}

// Probe runs a TCP-connect health check against the local listener.
// A successful connect means systemd is at least carrying the port
// open; deep TLS/REALITY validation lands in a later phase.
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
	return transport.ProbeResult{OK: true, Latency: latency, Notes: "tcp connect ok on " + addr}, nil
}

// Uninstall stops the unit and removes config + binary stays.
func (t *transportImpl) Uninstall(ctx context.Context) error { return t.mgr.Uninstall(ctx) }

func configFromOptions(opts transport.Options) (Config, error) {
	if opts.Domain == "" {
		return Config{}, errors.New("Options.Domain is required")
	}
	cfg := Config{
		Domain: opts.Domain,
		Dest:   stringFrom(opts.Extra, "xray.dest", "127.0.0.1:8443"),
		Mode:   Mode(stringFrom(opts.Extra, "xray.mode", string(ModeVision))),
	}
	if v, err := intFrom(opts.Extra, "xray.listen_port", DefaultListenPort); err != nil {
		return Config{}, err
	} else {
		cfg.ListenPort = v
	}

	uuid, err := requiredString(opts.Extra, "xray.uuid")
	if err != nil {
		return Config{}, err
	}
	cfg.UUID = uuid

	priv, err := requiredString(opts.Extra, "xray.private_key")
	if err != nil {
		return Config{}, err
	}
	cfg.PrivateKey = priv

	pub, err := requiredString(opts.Extra, "xray.public_key")
	if err != nil {
		return Config{}, err
	}
	cfg.PublicKey = pub

	ids, err := stringSliceFrom(opts.Extra, "xray.short_ids")
	if err != nil {
		return Config{}, err
	}
	cfg.ShortIDs = ids

	cfg.XHTTPPath = stringFrom(opts.Extra, "xray.xhttp_path", "")
	return cfg, nil
}

func stringFrom(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return def
	}
	return s
}

func intFrom(m map[string]any, key string, def int) (int, error) {
	if m == nil {
		return def, nil
	}
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	switch x := v.(type) {
	case int:
		return x, nil
	case int32:
		return int(x), nil
	case int64:
		return int(x), nil
	case float64: // JSON unmarshal default
		return int(x), nil
	default:
		return 0, fmt.Errorf("Extra[%q] not an int: %T", key, v)
	}
}

func requiredString(m map[string]any, key string) (string, error) {
	v := stringFrom(m, key, "")
	if v == "" {
		return "", fmt.Errorf("Extra[%q] is required", key)
	}
	return v, nil
}

func stringSliceFrom(m map[string]any, key string) ([]string, error) {
	if m == nil {
		return nil, fmt.Errorf("Extra[%q] is required", key)
	}
	v, ok := m[key]
	if !ok {
		return nil, fmt.Errorf("Extra[%q] is required", key)
	}
	switch x := v.(type) {
	case []string:
		if len(x) == 0 {
			return nil, fmt.Errorf("Extra[%q] is empty", key)
		}
		return x, nil
	case []any:
		out := make([]string, 0, len(x))
		for i, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("Extra[%q][%d] not a string: %T", key, i, item)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("Extra[%q] is empty", key)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("Extra[%q] not a string slice: %T", key, v)
	}
}

func init() {
	transport.Register(Name, New)
}
