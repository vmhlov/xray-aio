package naive

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/vmhlov/xray-aio/internal/transport"
)

// Name is the registry id for this transport.
const Name = "naive"

type transportImpl struct {
	mgr *Manager
}

// New returns a fresh naive Transport.
func New() transport.Transport {
	return &transportImpl{mgr: NewManager()}
}

// Name returns the canonical id.
func (t *transportImpl) Name() string { return Name }

// Install reads naive-specific knobs from Options.Extra and delegates
// to [Manager.Install].
//
// Required Extra keys:
//
//	naive.username           string
//	naive.password           string
//
// Optional Extra keys (with defaults):
//
//	naive.listen_port        int     (443)
//	naive.probe_resistance   string  (random 8-byte hex .invalid host)
//	naive.site_root          string  (Manager.Paths.SiteRoot)
//	naive.selfsteal_port     int     (8443)
//	naive.selfsteal_root     string  (Manager.Paths.SelfStealRoot)
//	naive.admin_socket       string  ("" — unix socket; "off" disables)
//	naive.build_url          string  (Caddy build service)
func (t *transportImpl) Install(ctx context.Context, opts transport.Options) error {
	o, err := optionsFrom(opts)
	if err != nil {
		return err
	}
	if buildURL := stringFrom(opts.Extra, "naive.build_url", ""); buildURL != "" {
		t.mgr.BuildURL = buildURL
	}
	return t.mgr.Install(ctx, o)
}

// Start brings the systemd unit up.
func (t *transportImpl) Start(ctx context.Context) error { return t.mgr.Start(ctx) }

// Stop tears the systemd unit down.
func (t *transportImpl) Stop(ctx context.Context) error { return t.mgr.Stop(ctx) }

// Status returns systemd state.
func (t *transportImpl) Status(ctx context.Context) (transport.Status, error) {
	active, raw, err := t.mgr.Status(ctx)
	if err != nil {
		return transport.Status{}, err
	}
	return transport.Status{Running: active, Notes: raw}, nil
}

// Probe runs a TCP-connect health check against the configured port.
// It re-derives the port from the Caddyfile on disk so a non-default
// port survives a CLI restart. Falls back to [DefaultListenPort] with
// a diagnostic in Notes when the file can't be read.
func (t *transportImpl) Probe(ctx context.Context) (transport.ProbeResult, error) {
	port, portErr := t.readConfiguredPort()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	start := time.Now()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	latency := time.Since(start).Milliseconds()
	prefix := ""
	if portErr != nil {
		prefix = "config unreadable (" + portErr.Error() + "); fell back to default port. "
	}
	if err != nil {
		return transport.ProbeResult{OK: false, Latency: latency, Notes: prefix + err.Error()}, nil
	}
	_ = conn.Close()
	return transport.ProbeResult{OK: true, Latency: latency, Notes: prefix + "tcp connect ok on " + addr}, nil
}

// Uninstall stops the unit and removes config tree.
func (t *transportImpl) Uninstall(ctx context.Context) error { return t.mgr.Uninstall(ctx) }

// readConfiguredPort scans the Caddyfile on disk for the first ":<port>"
// site block. We can't use a generic Caddyfile parser here without
// adding Caddy as a dependency, so we look for the site directive
// pattern Render() emits.
func (t *transportImpl) readConfiguredPort() (int, error) {
	body, err := readSmall(t.mgr.Paths.Caddyfile)
	if err != nil {
		return DefaultListenPort, err
	}
	port, err := parsePortFromCaddyfile(body)
	if err != nil {
		return DefaultListenPort, err
	}
	return port, nil
}

func optionsFrom(in transport.Options) (Options, error) {
	if in.Domain == "" {
		return Options{}, errors.New("Options.Domain is required")
	}
	user, err := requiredString(in.Extra, "naive.username")
	if err != nil {
		return Options{}, err
	}
	pass, err := requiredString(in.Extra, "naive.password")
	if err != nil {
		return Options{}, err
	}
	port, err := intFrom(in.Extra, "naive.listen_port", DefaultListenPort)
	if err != nil {
		return Options{}, err
	}
	selfStealPort, err := intFrom(in.Extra, "naive.selfsteal_port", DefaultSelfStealPort)
	if err != nil {
		return Options{}, err
	}
	probe := stringFrom(in.Extra, "naive.probe_resistance", "")
	if probe == "" {
		probe, err = randomProbeHost()
		if err != nil {
			return Options{}, err
		}
	}
	return Options{
		Domain:          in.Domain,
		Email:           in.Email,
		ListenPort:      port,
		Username:        user,
		Password:        pass,
		ProbeResistance: probe,
		SiteRoot:        stringFrom(in.Extra, "naive.site_root", ""),
		SelfStealPort:   selfStealPort,
		SelfStealRoot:   stringFrom(in.Extra, "naive.selfsteal_root", ""),
		AdminSocket:     stringFrom(in.Extra, "naive.admin_socket", ""),
	}, nil
}

// randomProbeHost returns a fresh hostname used to silence the active
// probe response. The .invalid TLD is reserved by RFC 2606 so the
// hostname is guaranteed to never resolve, which is the desired
// behaviour — the probe-resistance secret is never meant to be looked
// up.
func randomProbeHost() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random probe host: %w", err)
	}
	return hex.EncodeToString(b[:]) + ".invalid", nil
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
	case float64:
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

func init() {
	transport.Register(Name, New)
}
