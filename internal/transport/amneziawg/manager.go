package amneziawg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
)

// Version is the pinned upstream amneziawg-go release. Bump only
// after the binary has been exercised on a real VPS. amneziawg-go
// uses semver tags like `v0.2.17` (no `app/` prefix).
const Version = "0.2.17"

// ToolsVersion is the pinned amneziawg-tools (`awg`) release. The
// tools repo cuts dated tags; we pin a known-good one and update
// in lockstep with the daemon.
const ToolsVersion = "1.0.20260223"

// Paths is the on-disk layout xray-aio maintains for amneziawg.
type Paths struct {
	BinaryDaemon string // /usr/local/bin/amneziawg-go
	BinaryTool   string // /usr/local/bin/awg
	ConfigDir    string // /etc/xray-aio/amneziawg
	Config       string // /etc/xray-aio/amneziawg/awg0.conf
	UnitFile     string // /etc/systemd/system/xray-aio-amneziawg.service
	UnitName     string // xray-aio-amneziawg.service
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		BinaryDaemon: "/usr/local/bin/amneziawg-go",
		BinaryTool:   "/usr/local/bin/awg",
		ConfigDir:    "/etc/xray-aio/amneziawg",
		Config:       "/etc/xray-aio/amneziawg/awg0.conf",
		UnitFile:     "/etc/systemd/system/xray-aio-amneziawg.service",
		UnitName:     "xray-aio-amneziawg.service",
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

// Manager owns the amneziawg lifecycle.
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

// Install lays down both binaries (daemon + awg tool), the awg0
// config, and the systemd unit, then starts (or restarts) the
// service. Idempotent: re-running Install with a freshly rendered
// config picks up the change without operator intervention, exactly
// as the hysteria2 / naive / xray managers do.
func (m *Manager) Install(ctx context.Context, cfg Config) error {
	if err := m.ensureBinaries(ctx); err != nil {
		return fmt.Errorf("install amneziawg binaries: %w", err)
	}
	if err := m.writeConfig(cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	// awg0.conf carries the server private key — keep it 0600.
	// The systemd unit runs as root (CAP_NET_ADMIN is needed and
	// userspace caps without root are fragile under
	// NoNewPrivileges), so root:root + 0600 is the minimum.
	if _, err := m.Runner.Run(ctx, "chown", "root:root", m.Paths.Config); err != nil {
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
	// `restart` semantics match the rest of xray-aio: it starts a
	// stopped unit and restarts a running one — either way the
	// new awg0.conf is picked up. Using `enable --now` instead
	// would leave a running unit on the old config (the bug
	// fixed in PR #22 for xray/naive/hy2).
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

// Reload regenerates the config and asks systemd to restart the
// unit. amneziawg-go has no live-reload signal, so this is a hard
// restart — handshake state is rekeyed on the next packet.
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

// Uninstall stops the service, removes the unit file, the config
// tree, and the awg0 interface if it's still up. Idempotent.
func (m *Manager) Uninstall(ctx context.Context) error {
	_, _ = m.Runner.Run(ctx, "systemctl", "disable", "--now", m.Paths.UnitName)
	// The systemd ExecStop hook should already have torn down
	// awg0; this is the belt-and-suspenders cleanup for the case
	// where the unit died abnormally.
	_, _ = m.Runner.Run(ctx, "ip", "link", "del", "dev", "awg0")
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
	if err := os.MkdirAll(filepath.Dir(m.Paths.Config), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.Config, []byte(body), 0o600)
}

func (m *Manager) writeUnit() error {
	unit := strings.ReplaceAll(systemdUnitTemplate, "{{DAEMON}}", m.Paths.BinaryDaemon)
	unit = strings.ReplaceAll(unit, "{{TOOL}}", m.Paths.BinaryTool)
	unit = strings.ReplaceAll(unit, "{{CONFIG}}", m.Paths.Config)
	if err := os.MkdirAll(filepath.Dir(m.Paths.UnitFile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.UnitFile, []byte(unit), 0o644)
}

// ensureBinaries downloads amneziawg-go and awg if they're missing.
// We treat both as required: amneziawg-go is the daemon, awg
// applies the awg0.conf to the running interface (the daemon
// itself doesn't parse the file). Both are no-arch-suffix, no-tar
// flat binaries hosted on the xray-aio GitHub releases (built from
// upstream sources by [.github/workflows/release-amneziawg.yml] —
// upstream amneziawg-go/amneziawg-tools don't ship release assets).
//
// Each download is sha256-verified against a sidecar at
// `<url>.sha256` (also produced by the same release workflow). A
// missing sidecar, malformed digest, or content mismatch is a hard
// error — we'd rather refuse to install than silently land a
// truncated/corrupt/replaced binary on the operator's box.
func (m *Manager) ensureBinaries(ctx context.Context) error {
	specs := []struct {
		path string
		url  func() (string, error)
		name string
	}{
		{m.Paths.BinaryDaemon, func() (string, error) { return DaemonDownloadURL(Version, runtime.GOOS, runtime.GOARCH) }, "amneziawg-go"},
		{m.Paths.BinaryTool, func() (string, error) { return ToolDownloadURL(ToolsVersion, runtime.GOOS, runtime.GOARCH) }, "awg"},
	}
	for _, s := range specs {
		if info, err := os.Stat(s.path); err == nil && info.Mode().IsRegular() {
			continue
		}
		u, err := s.url()
		if err != nil {
			return fmt.Errorf("%s url: %w", s.name, err)
		}
		if err := m.fetchAndVerify(ctx, s.path, u, 0o755); err != nil {
			return fmt.Errorf("install %s: %w", s.name, err)
		}
	}
	return nil
}

// fetchAndVerify downloads the binary at url into dst (mode), after
// validating its content against the sha256 digest published at
// `url + ".sha256"`. The body is streamed through a hasher so we do
// not buffer the whole binary in memory — amneziawg-go is currently
// ~10 MB but the streaming write keeps the contract memory-bounded
// for any future binary size.
//
// Failure modes (all hard errors, none fall back to "install
// unverified"):
//   - sidecar fetch error / non-2xx → "fetch sha256"
//   - sidecar body that does not start with 64 hex chars → "sha256 sidecar"
//   - body fetch error → "fetch"
//   - hash mismatch → "sha256 mismatch" (and the partial file is removed)
func (m *Manager) fetchAndVerify(ctx context.Context, dst, rawURL string, mode os.FileMode) error {
	sumURL := rawURL + ".sha256"
	sumRC, err := m.Downloader.Get(ctx, sumURL)
	if err != nil {
		return fmt.Errorf("fetch sha256 %s: %w", sumURL, err)
	}
	sumBytes, err := io.ReadAll(sumRC)
	_ = sumRC.Close()
	if err != nil {
		return fmt.Errorf("read sha256 %s: %w", sumURL, err)
	}
	expected, err := parseSHA256Line(sumBytes)
	if err != nil {
		return fmt.Errorf("sha256 sidecar %s: %w", sumURL, err)
	}

	rc, err := m.Downloader.Get(ctx, rawURL)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = rc.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	h := sha256.New()
	if err := writeFromReader(dst, io.TeeReader(rc, h), mode); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		_ = os.Remove(dst)
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", rawURL, actual, expected)
	}
	return nil
}

// parseSHA256Line accepts the two formats `sha256sum(1)` produces:
//
//	<hex>  <name>     (binary mode, two spaces)
//	<hex> *<name>     (text-input flag, one space + asterisk)
//
// Only the leading 64-hex-character digest is consumed; the
// filename column is ignored because our sidecars are 1:1 with the
// binary URL anyway.
func parseSHA256Line(b []byte) (string, error) {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	if len(s) != 64 {
		return "", fmt.Errorf("expected 64-hex-char digest, got %q", s)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("malformed hex digest %q: %w", s, err)
	}
	return strings.ToLower(s), nil
}

// DaemonDownloadURL returns the URL to fetch amneziawg-go for the
// given host triple from the xray-aio project's own GitHub
// releases. The CI workflow that populates these releases lands in
// a follow-up PR (#28 in the Phase 2.2 sequence). Until that
// release exists the URL resolves to 404, ensureBinaries reports
// the failure cleanly, and an operator who wants to test ahead of
// time can pre-place /usr/local/bin/amneziawg-go manually — the
// os.Stat short-circuit at the top of ensureBinaries skips the
// download when the file is already present.
func DaemonDownloadURL(version, goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (amneziawg-go ships linux only here)", goos)
	}
	asset, ok := daemonLinuxAsset[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported GOARCH %q for linux", goarch)
	}
	tag := url.PathEscape("amneziawg-go-v" + version)
	return fmt.Sprintf(
		"https://github.com/vmhlov/xray-aio/releases/download/%s/%s",
		tag, asset,
	), nil
}

// ToolDownloadURL returns the URL to fetch the `awg` userspace
// configure-tool from amneziawg-tools, hosted alongside the daemon
// in xray-aio's own GitHub releases.
func ToolDownloadURL(version, goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (awg ships linux only here)", goos)
	}
	asset, ok := toolLinuxAsset[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported GOARCH %q for linux", goarch)
	}
	tag := url.PathEscape("amneziawg-tools-v" + version)
	return fmt.Sprintf(
		"https://github.com/vmhlov/xray-aio/releases/download/%s/%s",
		tag, asset,
	), nil
}

// daemonLinuxAsset maps Go arch names to the amneziawg-go binary
// names baked by xray-aio's release pipeline.
var daemonLinuxAsset = map[string]string{
	"amd64": "amneziawg-go-linux-amd64",
	"arm64": "amneziawg-go-linux-arm64",
}

// toolLinuxAsset maps Go arch names to the awg binary names baked
// alongside the daemon.
var toolLinuxAsset = map[string]string{
	"amd64": "awg-linux-amd64",
	"arm64": "awg-linux-arm64",
}

// writeFileAtomic creates or replaces dst with contents at mode
// using the temp-file + rename pattern. Mirrors the helper in the
// hysteria2 package.
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

// systemdUnitTemplate runs amneziawg-go in foreground mode (so
// systemd can supervise it cleanly) and uses ExecStartPost hooks to
// hand awg0.conf to `awg setconf`, raise the interface, and assign
// the server-side address. ExecStop tears the interface down so
// `systemctl restart` cleanly recreates it on the new config.
//
// Why not awg-quick(8)? awg-quick wraps the same setup steps but
// expects to manage its own resolv.conf hooks (for the [Interface]
// DNS line on the *peer* side, which makes sense for a client and
// not for a server) and prefers to be run interactively. Hand-rolling
// the systemd unit gives us exact control over the lifecycle.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed AmneziaWG (DPI-resistant WireGuard)
Documentation=https://docs.amnezia.org/documentation/amnezia-wg/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{DAEMON}} --foreground awg0
ExecStartPost={{TOOL}} setconf awg0 {{CONFIG}}
ExecStartPost=/sbin/ip link set up dev awg0
ExecStop=/sbin/ip link del awg0
Restart=on-failure
RestartSec=2s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_ADMIN

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
