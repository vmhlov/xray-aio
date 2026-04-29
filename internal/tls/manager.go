package tls

import (
	"archive/tar"
	"compress/gzip"
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

// CaddyVersion is the pinned upstream Caddy release this orchestrator
// installs. Bump only after we exercised it on a real VPS.
const CaddyVersion = "2.8.4"

// Paths is the on-disk layout xray-aio maintains for the Caddy
// frontend. All fields are absolute paths; defaults via [DefaultPaths].
type Paths struct {
	Binary       string // /usr/local/bin/caddy
	ConfigDir    string // /etc/xray-aio/caddy
	Caddyfile    string // /etc/xray-aio/caddy/Caddyfile
	SelfStealDir string // /var/lib/xray-aio/selfsteal
	UnitFile     string // /etc/systemd/system/xray-aio-caddy.service
	UnitName     string // xray-aio-caddy.service
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		Binary:       "/usr/local/bin/caddy",
		ConfigDir:    "/etc/xray-aio/caddy",
		Caddyfile:    "/etc/xray-aio/caddy/Caddyfile",
		SelfStealDir: DefaultSelfStealRoot,
		UnitFile:     "/etc/systemd/system/xray-aio-caddy.service",
		UnitName:     "xray-aio-caddy.service",
	}
}

// Runner executes external commands. Production uses [ExecRunner]; tests
// supply a fake that records invocations.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Downloader fetches HTTP resources. Production uses [HTTPDownloader];
// tests supply a fake that returns canned bytes.
type Downloader interface {
	Get(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager owns the Caddy lifecycle.
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
		Downloader: HTTPDownloader{Timeout: 5 * time.Minute},
	}
}

// Install lays down Caddy + selfsteal files + systemd unit and starts
// the service. Idempotent: running it twice is safe.
func (m *Manager) Install(ctx context.Context, opts Options) error {
	if err := m.ensureBinary(ctx); err != nil {
		return fmt.Errorf("install caddy binary: %w", err)
	}
	if err := m.writeSelfSteal(opts); err != nil {
		return fmt.Errorf("write selfsteal: %w", err)
	}
	if err := m.writeCaddyfile(opts); err != nil {
		return fmt.Errorf("write caddyfile: %w", err)
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

// Reload regenerates the Caddyfile and asks Caddy to re-read it.
func (m *Manager) Reload(ctx context.Context, opts Options) error {
	if err := m.writeCaddyfile(opts); err != nil {
		return err
	}
	_, err := m.Runner.Run(ctx, "systemctl", "reload", m.Paths.UnitName)
	return err
}

// Status reports whether the unit is currently active.
func (m *Manager) Status(ctx context.Context) (active bool, raw string, err error) {
	out, runErr := m.Runner.Run(ctx, "systemctl", "is-active", m.Paths.UnitName)
	raw = strings.TrimSpace(string(out))
	// systemctl is-active exits 3 when inactive — that is not a hard
	// error from our perspective.
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
	for _, p := range []string{m.Paths.UnitFile, m.Paths.Caddyfile} {
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

func (m *Manager) writeCaddyfile(opts Options) error {
	if opts.SelfStealRoot == "" {
		opts.SelfStealRoot = m.Paths.SelfStealDir
	}
	body, err := Render(opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.Paths.Caddyfile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.Caddyfile, []byte(body), 0o644)
}

func (m *Manager) writeSelfSteal(opts Options) error {
	root := opts.SelfStealRoot
	if root == "" {
		root = m.Paths.SelfStealDir
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	idx := filepath.Join(root, "index.html")
	if _, err := os.Stat(idx); err == nil {
		// Operator-provided page already in place — leave alone.
		return nil
	}
	return writeFileAtomic(idx, SelfStealIndex, 0o644)
}

func (m *Manager) writeUnit() error {
	unit := strings.ReplaceAll(systemdUnitTemplate, "{{BINARY}}", m.Paths.Binary)
	unit = strings.ReplaceAll(unit, "{{CONFIG}}", m.Paths.Caddyfile)
	if err := os.MkdirAll(filepath.Dir(m.Paths.UnitFile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.UnitFile, []byte(unit), 0o644)
}

func (m *Manager) ensureBinary(ctx context.Context) error {
	if info, err := os.Stat(m.Paths.Binary); err == nil && info.Mode().IsRegular() {
		return nil
	}
	url := caddyDownloadURL(CaddyVersion, runtime.GOOS, runtime.GOARCH)
	rc, err := m.Downloader.Get(ctx, url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = rc.Close() }()
	if err := os.MkdirAll(filepath.Dir(m.Paths.Binary), 0o755); err != nil {
		return err
	}
	return extractCaddy(rc, m.Paths.Binary)
}

// caddyDownloadURL returns the GitHub release asset URL for an upstream
// Caddy build. We use the official static-binary tarball.
func caddyDownloadURL(version, goos, goarch string) string {
	// Caddy release naming: caddy_2.8.4_linux_amd64.tar.gz
	return fmt.Sprintf(
		"https://github.com/caddyserver/caddy/releases/download/v%s/caddy_%s_%s_%s.tar.gz",
		version, version, goos, goarch,
	)
}

// extractCaddy reads a Caddy tarball from r and writes the bare 'caddy'
// binary to dst with mode 0755.
func extractCaddy(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("caddy binary not found in tarball")
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		if hdr.Name != "caddy" {
			continue
		}
		return writeFromReader(dst, tr, 0o755)
	}
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

// systemdUnitTemplate is a hardened, sandboxed unit.
//
//   - CAP_NET_BIND_SERVICE lets us bind 80/443 without running as root.
//   - RuntimeDirectory=xray-aio creates /run/xray-aio at start (mode
//     0750, owned by caddy:caddy) and removes it on stop, so the
//     admin socket at [DefaultAdminSocket] has a place to live.
//   - ExecReload uses `caddy reload` which talks to that admin socket;
//     this works in the default config because we never emit
//     `admin off` unless the operator explicitly asks for it.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed Caddy
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
RuntimeDirectory=xray-aio
RuntimeDirectoryMode=0750
ExecStart={{BINARY}} run --environ --config {{CONFIG}}
ExecReload={{BINARY}} reload --config {{CONFIG}} --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
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
