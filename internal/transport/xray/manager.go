package xray

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Version is the pinned upstream Xray-core release we install. Bump
// only after we exercised the binary on a real VPS.
const Version = "26.3.27"

// Paths is the on-disk layout xray-aio maintains for Xray-core. All
// fields are absolute paths.
type Paths struct {
	Binary    string // /usr/local/bin/xray
	ConfigDir string // /etc/xray-aio/xray
	Config    string // /etc/xray-aio/xray/config.json
	UnitFile  string // /etc/systemd/system/xray-aio-xray.service
	UnitName  string // xray-aio-xray.service
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		Binary:    "/usr/local/bin/xray",
		ConfigDir: "/etc/xray-aio/xray",
		Config:    "/etc/xray-aio/xray/config.json",
		UnitFile:  "/etc/systemd/system/xray-aio-xray.service",
		UnitName:  "xray-aio-xray.service",
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

// Manager owns the Xray-core lifecycle.
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

// Install lays down the binary, the config and the systemd unit, then
// starts the service. Idempotent.
func (m *Manager) Install(ctx context.Context, cfg Config) error {
	if err := m.ensureBinary(ctx); err != nil {
		return fmt.Errorf("install xray binary: %w", err)
	}
	if err := m.writeConfig(cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := m.writeUnit(); err != nil {
		return fmt.Errorf("write systemd unit: %w", err)
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if _, err := m.Runner.Run(ctx, "systemctl", "enable", "--now", m.Paths.UnitName); err != nil {
		return fmt.Errorf("enable+start: %w", err)
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
// Xray-core has no live-reload protocol, so this is start+stop.
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
	return writeFileAtomic(m.Paths.Config, []byte(body), 0o600)
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
	return extractXray(rc, m.Paths.Binary)
}

// DownloadURL returns the Xray-core release-asset URL for the given
// host triple. Returns an error for unsupported combinations rather
// than synthesising a bad URL — fail fast at install time.
func DownloadURL(version, goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (Xray release ships linux only)", goos)
	}
	asset, ok := linuxAsset[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported GOARCH %q for linux", goarch)
	}
	return fmt.Sprintf(
		"https://github.com/XTLS/Xray-core/releases/download/v%s/%s",
		version, asset,
	), nil
}

// linuxAsset maps Go arch names to upstream Xray release-asset names.
// Naming verified against
// https://api.github.com/repos/XTLS/Xray-core/releases/latest.
var linuxAsset = map[string]string{
	"amd64": "Xray-linux-64.zip",
	"arm64": "Xray-linux-arm64-v8a.zip",
	"386":   "Xray-linux-32.zip",
}

// extractXray reads a Xray-core ZIP from r and writes the bare 'xray'
// binary to dst with mode 0755. It buffers the whole archive in memory
// (~25MB) because archive/zip needs a ReaderAt.
func extractXray(r io.Reader, dst string) error {
	buf, err := io.ReadAll(io.LimitReader(r, 64<<20)) // 64MB hard cap
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return fmt.Errorf("zip open: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != "xray" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("zip entry: %w", err)
		}
		err = writeFromReader(dst, rc, 0o755)
		_ = rc.Close()
		return err
	}
	return errors.New("xray binary not found in archive")
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

// systemdUnitTemplate runs Xray as a dedicated, sandboxed system user.
// CAP_NET_BIND_SERVICE lets us listen on 443 without root.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed Xray-core
Documentation=https://xtls.github.io/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xray
Group=xray
ExecStart={{BINARY}} run -config {{CONFIG}}
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
func (h HTTPDownloader) Get(ctx context.Context, url string) (io.ReadCloser, error) {
	cli := &http.Client{Timeout: h.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, url)
	}
	return resp.Body, nil
}
