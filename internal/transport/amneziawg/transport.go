package amneziawg

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vmhlov/xray-aio/internal/transport"
)

// Name is the registry id for this transport.
const Name = "amneziawg"

type transportImpl struct {
	mgr *Manager
}

// New returns a fresh amneziawg Transport ready to register.
func New() transport.Transport {
	return &transportImpl{mgr: NewManager()}
}

// Name returns the canonical id.
func (t *transportImpl) Name() string { return Name }

// Install reads amneziawg-specific knobs from Options.Extra and
// delegates to [Manager.Install].
//
// Required Extra keys (orchestrator generates these on first install
// and persists them in state.json so subsequent runs don't
// invalidate the peer's existing .conf):
//
//	amneziawg.private_key       string  (base64 32B Curve25519 secret)
//	amneziawg.peer_public_key   string  (base64 32B peer pubkey)
//	amneziawg.jc                int
//	amneziawg.jmin              int
//	amneziawg.jmax              int
//	amneziawg.s1                int
//	amneziawg.s2                int
//	amneziawg.h1                uint32
//	amneziawg.h2                uint32
//	amneziawg.h3                uint32
//	amneziawg.h4                uint32
//
// Optional Extra keys (with defaults applied in Render via
// Config.resolvedDefaults):
//
//	amneziawg.peer_preshared    string  (no PSK if absent)
//	amneziawg.server_address    string  (DefaultServerAddress)
//	amneziawg.peer_address      string  (DefaultPeerAddress)
//	amneziawg.listen_port       int     (DefaultListenPort)
//	amneziawg.dns               string  (DefaultDNS)
//	amneziawg.mtu               int     (DefaultMTU)
//
// Domain in Options is used for the peer-side Endpoint string when
// a follow-up subscription PR renders the .conf for the client; the
// server-side install proper does not need Domain (amneziawg uses
// its own crypto, not TLS).
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
// AmneziaWG speaks UDP — like hysteria2's probe, this binds the
// local side without sending bytes, which only fails when the
// kernel can't reserve a 4-tuple. Good enough to tell that the
// systemd unit is at least carrying its UDP socket. Deeper
// handshake validation lands when there's a real client harness
// (Phase 3 UX).
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
	priv, err := requiredString(opts.Extra, "amneziawg.private_key")
	if err != nil {
		return Config{}, err
	}
	peerPub, err := requiredString(opts.Extra, "amneziawg.peer_public_key")
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		PrivateKey:       priv,
		PeerPublicKey:    peerPub,
		PeerPresharedKey: stringFrom(opts.Extra, "amneziawg.peer_preshared", ""),
		ServerAddress:    stringFrom(opts.Extra, "amneziawg.server_address", ""),
		PeerAddress:      stringFrom(opts.Extra, "amneziawg.peer_address", ""),
		DNS:              stringFrom(opts.Extra, "amneziawg.dns", ""),
	}
	port, err := intFrom(opts.Extra, "amneziawg.listen_port", 0)
	if err != nil {
		return Config{}, err
	}
	cfg.ListenPort = port
	mtu, err := intFrom(opts.Extra, "amneziawg.mtu", 0)
	if err != nil {
		return Config{}, err
	}
	cfg.MTU = mtu

	obf, err := obfuscationFromOptions(opts.Extra)
	if err != nil {
		return Config{}, err
	}
	cfg.Obfuscation = obf
	if opts.Domain != "" {
		// Endpoint is needed only for peer-side .conf rendering.
		// The server-side awg0.conf doesn't reference it. We still
		// stash it on the Config so a downstream RenderPeer call
		// works without re-plumbing.
		listenPort := port
		if listenPort == 0 {
			listenPort = DefaultListenPort
		}
		cfg.Endpoint = net.JoinHostPort(opts.Domain, strconv.Itoa(listenPort))
	}
	return cfg, nil
}

func obfuscationFromOptions(m map[string]any) (Obfuscation, error) {
	jc, err := requiredInt(m, "amneziawg.jc")
	if err != nil {
		return Obfuscation{}, err
	}
	jmin, err := requiredInt(m, "amneziawg.jmin")
	if err != nil {
		return Obfuscation{}, err
	}
	jmax, err := requiredInt(m, "amneziawg.jmax")
	if err != nil {
		return Obfuscation{}, err
	}
	s1, err := requiredInt(m, "amneziawg.s1")
	if err != nil {
		return Obfuscation{}, err
	}
	s2, err := requiredInt(m, "amneziawg.s2")
	if err != nil {
		return Obfuscation{}, err
	}
	h1, err := requiredUint32(m, "amneziawg.h1")
	if err != nil {
		return Obfuscation{}, err
	}
	h2, err := requiredUint32(m, "amneziawg.h2")
	if err != nil {
		return Obfuscation{}, err
	}
	h3, err := requiredUint32(m, "amneziawg.h3")
	if err != nil {
		return Obfuscation{}, err
	}
	h4, err := requiredUint32(m, "amneziawg.h4")
	if err != nil {
		return Obfuscation{}, err
	}
	return Obfuscation{
		Jc:   jc,
		Jmin: jmin,
		Jmax: jmax,
		S1:   s1,
		S2:   s2,
		H1:   h1,
		H2:   h2,
		H3:   h3,
		H4:   h4,
	}, nil
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

// intFrom accepts int, int64, float64, or numeric strings and returns
// the value as int. Returns def when the key is absent.
func intFrom(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	return coerceInt(key, v)
}

// requiredInt is intFrom that errors on missing key.
func requiredInt(m map[string]any, key string) (int, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("Extra[%q] is required", key)
	}
	return coerceInt(key, v)
}

// requiredUint32 forces the value into a uint32. Same coercion shape
// as requiredInt; range-checked because the magic-header obfuscation
// fields are uint32 on the wire.
func requiredUint32(m map[string]any, key string) (uint32, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("Extra[%q] is required", key)
	}
	switch x := v.(type) {
	case uint32:
		return x, nil
	case int:
		if x < 0 || int64(x) > int64(^uint32(0)) {
			return 0, fmt.Errorf("Extra[%q] %d out of uint32 range", key, x)
		}
		return uint32(x), nil
	case int64:
		if x < 0 || x > int64(^uint32(0)) {
			return 0, fmt.Errorf("Extra[%q] %d out of uint32 range", key, x)
		}
		return uint32(x), nil
	case float64:
		if x < 0 || x > float64(^uint32(0)) {
			return 0, fmt.Errorf("Extra[%q] %v out of uint32 range", key, x)
		}
		return uint32(x), nil
	case string:
		// Parse uint64 first so values >= 2^31 (legal uint32) don't
		// trip strconv.Atoi's int range on 32-bit hosts.
		n, err := strconv.ParseUint(x, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("Extra[%q] not a uint32: %q", key, x)
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("Extra[%q] not numeric: %T", key, v)
	}
}

func coerceInt(key string, v any) (int, error) {
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
