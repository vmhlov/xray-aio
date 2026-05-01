package naive

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
// exec'ing the unified Caddy. Must match User=/Group= in
// [systemdUnitTemplate]. The name "caddy" matches upstream's deb
// package convention so a Caddy that is later replaced through the
// distro package keeps owning the same /var/lib/caddy data tree.
const systemUser = "caddy"

// Paths is the on-disk layout the manager owns. All paths absolute.
type Paths struct {
	Binary        string // /usr/local/bin/caddy-naive
	ConfigDir     string // /etc/xray-aio/naive
	Caddyfile     string // /etc/xray-aio/naive/Caddyfile
	SiteRoot      string // /var/lib/xray-aio/naive-selfsteal
	SelfStealRoot string // /var/lib/xray-aio/selfsteal
	UnitFile      string // /etc/systemd/system/xray-aio-naive.service
	UnitName      string // xray-aio-naive.service
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		Binary:        "/usr/local/bin/caddy-naive",
		ConfigDir:     "/etc/xray-aio/naive",
		Caddyfile:     "/etc/xray-aio/naive/Caddyfile",
		SiteRoot:      DefaultSiteRoot,
		SelfStealRoot: DefaultSelfStealRoot,
		UnitFile:      "/etc/systemd/system/xray-aio-naive.service",
		UnitName:      "xray-aio-naive.service",
	}
}

// Runner executes external commands. Production uses [ExecRunner];
// tests supply a fake.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Downloader fetches HTTP resources. Production uses [HTTPDownloader].
type Downloader interface {
	Get(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager owns the unified Caddy-with-forwardproxy lifecycle. One
// Caddy instance terminates two HTTPS sites under the same domain:
// the public NaïveProxy listener (forward_proxy + selfsteal
// fallback) and the loopback REALITY-upstream selfsteal site. Both
// share an ACME account and cert store via Caddy's auto-HTTPS, so
// only one HTTP-01 challenge is needed per renewal.
type Manager struct {
	Paths      Paths
	Runner     Runner
	Downloader Downloader

	// BuildURL overrides the default Caddy build-service URL. Empty
	// → DefaultBuildURL is used. Mostly a test seam, also lets an
	// operator point at a self-hosted mirror or at klzgrad's
	// hardened @naive fork.
	BuildURL string
}

// NewManager returns a Manager wired with production runner+downloader.
func NewManager() *Manager {
	return &Manager{
		Paths:      DefaultPaths(),
		Runner:     ExecRunner{},
		Downloader: HTTPDownloader{Timeout: 10 * time.Minute},
	}
}

// Install lays down the binary, the Caddyfile, the selfsteal index
// and the systemd unit, then starts (or restarts) the service.
// Idempotent — re-running with a freshly rendered Caddyfile picks
// up the change without operator intervention.
func (m *Manager) Install(ctx context.Context, opts Options) error {
	if err := m.ensureBinary(ctx); err != nil {
		return fmt.Errorf("install caddy-naive binary: %w", err)
	}
	if err := sysuser.Ensure(ctx, m.Runner, systemUser); err != nil {
		return fmt.Errorf("ensure system user: %w", err)
	}
	resolved := opts
	if resolved.SiteRoot == "" {
		resolved.SiteRoot = m.Paths.SiteRoot
	}
	if resolved.SelfStealRoot == "" {
		resolved.SelfStealRoot = m.Paths.SelfStealRoot
	}
	if err := m.writeCaddyfile(resolved); err != nil {
		return fmt.Errorf("write Caddyfile: %w", err)
	}
	// Caddyfile carries forward_proxy basic_auth credentials. Stays
	// mode 0640; we hand the group to the freshly-ensured caddy
	// group so the unit can read it as User=caddy without exposing
	// the file to other local users.
	if _, err := m.Runner.Run(ctx, "chown", "root:"+systemUser, m.Paths.Caddyfile); err != nil {
		return fmt.Errorf("chown Caddyfile: %w", err)
	}
	if err := m.writeSiteRoot(resolved.SiteRoot); err != nil {
		return fmt.Errorf("write site root: %w", err)
	}
	if err := m.writeSiteRoot(resolved.SelfStealRoot); err != nil {
		return fmt.Errorf("write selfsteal root: %w", err)
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
	// running one — either way the new Caddyfile is picked up.
	// Using `enable --now` instead would leave a running unit on
	// the old config, which is the bug this Install method existed
	// to avoid.
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

// Reload writes a new Caddyfile and asks Caddy (via systemd) to
// reload it through the admin socket. Caddy supports zero-downtime
// reloads when the admin endpoint is reachable.
func (m *Manager) Reload(ctx context.Context, opts Options) error {
	resolved := opts
	if resolved.SiteRoot == "" {
		resolved.SiteRoot = m.Paths.SiteRoot
	}
	if resolved.SelfStealRoot == "" {
		resolved.SelfStealRoot = m.Paths.SelfStealRoot
	}
	if err := m.writeCaddyfile(resolved); err != nil {
		return err
	}
	_, err := m.Runner.Run(ctx, "systemctl", "reload", m.Paths.UnitName)
	return err
}

// Status reports systemd's view of the unit.
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

// Uninstall stops the service and removes the unit + config tree.
// The binary stays on disk so a subsequent Install is fast (and we
// never download megabytes for an idempotent re-run). Idempotent.
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

func (m *Manager) writeCaddyfile(o Options) error {
	body, err := Render(o)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.Paths.Caddyfile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.Caddyfile, []byte(body), 0o640)
}

// writeSiteRoot installs the embedded fallback index.html under
// siteRoot, but only when the directory has no index file yet — so an
// operator who hand-rolled their own selfsteal page never has it
// silently overwritten by a re-Install.
func (m *Manager) writeSiteRoot(siteRoot string) error {
	if err := os.MkdirAll(siteRoot, 0o755); err != nil {
		return err
	}
	indexPath := filepath.Join(siteRoot, "index.html")
	if _, err := os.Stat(indexPath); err == nil {
		return nil
	}
	return writeFileAtomic(indexPath, SelfStealIndex(), 0o644)
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
	urlStr := m.BuildURL
	if urlStr == "" {
		var err error
		urlStr, err = DefaultBuildURL(runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}
	}
	rc, err := m.Downloader.Get(ctx, urlStr)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", urlStr, err)
	}
	defer func() { _ = rc.Close() }()
	if err := os.MkdirAll(filepath.Dir(m.Paths.Binary), 0o755); err != nil {
		return err
	}
	return writeFromReader(m.Paths.Binary, rc, 0o755)
}

// DefaultBuildURL returns the official Caddy build-service URL that
// produces a Caddy binary with the forwardproxy plugin compiled in.
//
// The build service does not pin Caddy versions; it always builds
// against the current stable. For reproducible builds operators
// should set [Manager.BuildURL] to a self-hosted asset.
func DefaultBuildURL(goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (build service serves linux/darwin/windows; we only support linux for now)", goos)
	}
	switch goarch {
	case "amd64", "arm64", "arm", "386":
	default:
		return "", fmt.Errorf("unsupported GOARCH %q", goarch)
	}
	q := url.Values{}
	q.Set("os", goos)
	q.Set("arch", goarch)
	q.Set("p", "github.com/caddyserver/forwardproxy")
	return "https://caddyserver.com/api/download?" + q.Encode(), nil
}

// writeFileAtomic creates or replaces dst at mode using temp + rename.
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

// systemdUnitTemplate hardens the unified Caddy with a dedicated
// user, ProtectSystem=full, RuntimeDirectory for the admin socket,
// StateDirectory for the ACME cert store, and CAP_NET_BIND_SERVICE
// so the process can listen on 443/80.
//
// XDG_DATA_HOME and HOME both point at /var/lib/caddy because Caddy
// resolves its certificate cache at "{$XDG_DATA_HOME-{$HOME/.local/
// share}}/caddy"; without either env var Caddy falls back to a
// /nonexistent home and HTTP-01 issuance fails before it leaves
// memory.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed Caddy (NaïveProxy forward_proxy)
Documentation=https://caddyserver.com/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
RuntimeDirectory=xray-aio
RuntimeDirectoryMode=0750
StateDirectory=caddy
StateDirectoryMode=0700
Environment=HOME=/var/lib/caddy
Environment=XDG_DATA_HOME=/var/lib/caddy
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

// Get issues a GET and returns the response body. The caller closes it.
func (h HTTPDownloader) Get(ctx context.Context, urlStr string) (io.ReadCloser, error) {
	cli := &http.Client{Timeout: h.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("http %d for %s", resp.StatusCode, urlStr)
	}
	return resp.Body, nil
}
