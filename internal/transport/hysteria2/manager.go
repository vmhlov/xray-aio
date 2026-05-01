package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vmhlov/xray-aio/internal/sysuser"
)

// systemUser is the unprivileged account systemd drops to before
// exec'ing hysteria. Reuses the `caddy` user the naive transport
// already creates so hysteria 2 can read Caddy's LE certificate
// store without a separate group/permissions dance. Trade-off
// documented in doc.go.
const systemUser = "caddy"

// Version is the pinned upstream Hysteria 2 release. Bump only after
// the binary has been exercised on a real VPS; upstream tags follow
// the `app/v<semver>` shape.
const Version = "2.8.2"

// Paths is the on-disk layout xray-aio maintains for hysteria 2.
type Paths struct {
	Binary    string // /usr/local/bin/hysteria
	ConfigDir string // /etc/xray-aio/hysteria2
	Config    string // /etc/xray-aio/hysteria2/config.yaml
	UnitFile  string // /etc/systemd/system/xray-aio-hysteria2.service
	UnitName  string // xray-aio-hysteria2.service
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		Binary:    "/usr/local/bin/hysteria",
		ConfigDir: "/etc/xray-aio/hysteria2",
		Config:    "/etc/xray-aio/hysteria2/config.yaml",
		UnitFile:  "/etc/systemd/system/xray-aio-hysteria2.service",
		UnitName:  "xray-aio-hysteria2.service",
	}
}

// Runner executes external commands. Production uses [ExecRunner];
// tests supply a fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Downloader fetches HTTP resources. Production uses [HTTPDownloader];
// tests supply a fake.
type Downloader interface {
	Get(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager owns the hysteria 2 lifecycle.
type Manager struct {
	Paths      Paths
	Runner     Runner
	Downloader Downloader
}

// NewManager returns a Manager wired with production runner+downloader.
func NewManager() *Manager {
	return &Manager{
		Paths:      DefaultPaths(),
		Runner:     ExecRunner{},
		Downloader: HTTPDownloader{Timeout: 10 * time.Minute},
	}
}

// Install lays down the binary, the config and the systemd unit,
// then starts (or restarts) the service. Idempotent: re-running
// Install with a freshly rendered config picks up the change
// without operator intervention.
func (m *Manager) Install(ctx context.Context, cfg Config) error {
	if err := m.ensureBinary(ctx); err != nil {
		return fmt.Errorf("install hysteria binary: %w", err)
	}
	if err := sysuser.Ensure(ctx, m.Runner, systemUser); err != nil {
		return fmt.Errorf("ensure system user: %w", err)
	}
	if err := m.writeConfig(cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	// Config holds the auth password, so it stays mode 0640. The
	// hysteria service runs as `caddy` and needs to read it.
	if _, err := m.Runner.Run(ctx, "chown", "root:"+systemUser, m.Paths.Config); err != nil {
		return fmt.Errorf("chown config: %w", err)
	}
	if err := m.writeUnit(); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "enable", m.Paths.UnitName); err != nil {
		return fmt.Errorf("enable: %w", err)
	}
	// `systemctl restart` starts a stopped unit and restarts a
	// running one — either way the new config is picked up. Using
	// `enable --now` instead would leave a running unit on the old
	// config, which is the bug this Install method existed to avoid.
	if _, err := m.Runner.Run(ctx, "systemctl", "restart", m.Paths.UnitName); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return nil
}

// Start brings the service up.
func (m *Manager) Start(ctx context.Context) error {
	_, err := m.Runner.Run(ctx, "systemctl", "start", m.Paths.UnitName)
	return err
}

// Stop tears the service down without removing config.
func (m *Manager) Stop(ctx context.Context) error {
	_, err := m.Runner.Run(ctx, "systemctl", "stop", m.Paths.UnitName)
	return err
}

// Reload regenerates the config and asks systemd to restart the unit.
// Hysteria 2 has no live-reload signal, so this is start+stop.
func (m *Manager) Reload(ctx context.Context, cfg Config) error {
	if err := m.writeConfig(cfg); err != nil {
		return err
	}
	_, err := m.Runner.Run(ctx, "systemctl", "restart", m.Paths.UnitName)
	return err
}

// Status reports whether the unit is currently active.
func (m *Manager) Status(ctx context.Context) (active bool, raw string, err error) {
	out, runErr := m.Runner.Run(ctx, "systemctl", "is-active", m.Paths.UnitName)
	raw = strings.TrimSpace(string(out))
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			// `is-active` exits non-zero when the unit is not
			// active, but the stdout still carries the precise
			// state ("inactive", "failed", …). Surface that.
			return raw == "active", raw, nil
		}
		return false, raw, runErr
	}
	return raw == "active", raw, nil
}

// Uninstall stops the service, removes the unit file and config tree.
// Idempotent.
func (m *Manager) Uninstall(ctx context.Context) error {
	_, _ = m.Runner.Run(ctx, "systemctl", "disable", "--now", m.Paths.UnitName)
	for _, p := range []string{m.Paths.UnitFile, m.Paths.Config} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	if err := os.RemoveAll(m.Paths.ConfigDir); err != nil {
		return fmt.Errorf("remove %s: %w", m.Paths.ConfigDir, err)
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	return nil
}

func (m *Manager) writeConfig(cfg Config) error {
	body, err := Render(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.Paths.Config), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.Config, []byte(body), 0o640)
}

func (m *Manager) writeUnit() error {
	unit := strings.ReplaceAll(systemdUnitTemplate, "{{BINARY}}", m.Paths.Binary)
	unit = strings.ReplaceAll(unit, "{{CONFIG}}", m.Paths.Config)
	if err := os.MkdirAll(filepath.Dir(m.Paths.UnitFile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.UnitFile, []byte(unit), 0o644)
}

func (m *Manager) ensureBinary(ctx context.Context) error {
	if info, err := os.Stat(m.Paths.Binary); err == nil && info.Mode().IsRegular() {
		return nil
	}
	url, err := DownloadURL(Version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	rc, err := m.Downloader.Get(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = rc.Close() }()
	if err := os.MkdirAll(filepath.Dir(m.Paths.Binary), 0o755); err != nil {
		return err
	}
	return writeFromReader(m.Paths.Binary, rc, 0o755)
}

// DownloadURL returns the Hysteria 2 release-asset URL for the given
// host triple. apernet/hysteria publishes flat binaries (not archives)
// per arch and uses the `app/v<semver>` tag shape, which means the
// `/` in the tag has to be percent-encoded for the GitHub asset path.
func DownloadURL(version, goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (Hysteria 2 release ships linux only here)", goos)
	}
	asset, ok := linuxAsset[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported GOARCH %q for linux", goarch)
	}
	tag := url.PathEscape("app/v" + version)
	return fmt.Sprintf(
		"https://github.com/apernet/hysteria/releases/download/%s/%s",
		tag, asset,
	), nil
}

// linuxAsset maps Go arch names to upstream Hysteria 2 release-asset
// names. Verified against
// https://api.github.com/repos/apernet/hysteria/releases/latest.
var linuxAsset = map[string]string{
	"amd64": "hysteria-linux-amd64",
	"arm64": "hysteria-linux-arm64",
	"386":   "hysteria-linux-386",
	"arm":   "hysteria-linux-arm",
}

// writeFileAtomic creates or replaces dst with contents at mode using
// the temp-file + rename pattern.
func writeFileAtomic(dst string, contents []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

func writeFromReader(dst string, r io.Reader, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := io.Copy(tmp, r); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// systemdUnitTemplate runs hysteria 2 as the same system user Caddy
// runs under. Hysteria reads its TLS cert + key from disk on every
// QUIC handshake, so Caddy can renew the cert under the unit and
// hysteria picks it up without a restart. CAP_NET_BIND_SERVICE is
// needed because port 443/UDP requires the same capability as TCP/443.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed Hysteria 2
Documentation=https://v2.hysteria.network/
After=network-online.target xray-aio-naive.service
Wants=network-online.target

[Service]
Type=simple
User=caddy
Group=caddy
ExecStart={{BINARY}} server --config {{CONFIG}}
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`

// ExecRunner is the production [Runner].
type ExecRunner struct{}

// Run shells out via os/exec.CommandContext.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// HTTPDownloader is the production [Downloader].
type HTTPDownloader struct {
	Timeout time.Duration
}

// Get issues a GET and returns the response body. The caller must
// close it.
func (d HTTPDownloader) Get(ctx context.Context, rawURL string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: d.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: status %s", rawURL, resp.Status)
	}
	return resp.Body, nil
}
