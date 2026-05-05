package mtproto

import (
	"archive/tar"
	"compress/gzip"
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

	"github.com/vmhlov/xray-aio/internal/sysuser"
)

// systemUser is the unprivileged account systemd drops to before
// exec'ing telemt. A dedicated user — not reusing `caddy` the way
// hysteria2 does — because telemt doesn't read Caddy's LE store:
// Fake-TLS generates its own ephemeral cert fingerprint on the fly.
const systemUser = "telemt"

// Version is the pinned upstream telemt release. Bump only after
// the binary has been exercised on a real VPS. Upstream tags are
// bare semver — no `v` prefix, no subdirectory — so the asset URL
// construction is simpler than Hysteria 2's.
const Version = "3.4.10"

// Paths is the on-disk layout xray-aio maintains for telemt.
type Paths struct {
	Binary    string // /usr/local/bin/telemt
	ConfigDir string // /etc/xray-aio/mtproto
	Config    string // /etc/xray-aio/mtproto/telemt.toml
	UnitFile  string // /etc/systemd/system/xray-aio-mtproto.service
	UnitName  string // xray-aio-mtproto.service
	HomeDir   string // /opt/telemt (systemUser's home, must exist)
}

// DefaultPaths returns the production layout. Tests pass their own
// [Paths] rooted under t.TempDir().
func DefaultPaths() Paths {
	return Paths{
		Binary:    "/usr/local/bin/telemt",
		ConfigDir: "/etc/xray-aio/mtproto",
		Config:    "/etc/xray-aio/mtproto/telemt.toml",
		UnitFile:  "/etc/systemd/system/xray-aio-mtproto.service",
		UnitName:  "xray-aio-mtproto.service",
		HomeDir:   "/opt/telemt",
	}
}

// Runner executes external commands. Production uses [ExecRunner];
// tests supply a fake. Same contract as hysteria2.Runner.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Downloader fetches HTTP resources. Production uses [HTTPDownloader];
// tests supply a fake.
type Downloader interface {
	Get(ctx context.Context, url string) (io.ReadCloser, error)
}

// Manager owns the telemt lifecycle.
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
// without operator intervention, matching the hysteria2/amneziawg
// contract.
func (m *Manager) Install(ctx context.Context, cfg Config) error {
	if err := m.ensureBinary(ctx); err != nil {
		return fmt.Errorf("install telemt binary: %w", err)
	}
	if err := sysuser.Ensure(ctx, m.Runner, systemUser); err != nil {
		return fmt.Errorf("ensure system user: %w", err)
	}
	if err := m.writeConfig(cfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	// Config holds the Fake-TLS secret, so it stays mode 0640. The
	// telemt service runs as `telemt` and needs to read it.
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
	// config (the bug fixed in PR #22 for xray/naive/hy2).
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
// telemt has a live SIGHUP config reload path, but we use restart to
// match the semantics of every other xray-aio transport — predictable
// behaviour over marginal uptime gains during a config change.
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
// The binary in /usr/local/bin and the system user are left alone —
// they're cheap to keep and re-installing costs a fresh download
// otherwise. Mirrors hysteria2.Manager.Uninstall.
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
	unit = strings.ReplaceAll(unit, "{{HOME}}", m.Paths.HomeDir)
	unit = strings.ReplaceAll(unit, "{{USER}}", systemUser)
	if err := os.MkdirAll(filepath.Dir(m.Paths.UnitFile), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(m.Paths.UnitFile, []byte(unit), 0o644)
}

// ensureBinary downloads and verifies the telemt binary if it's
// missing. Upstream telemt publishes a .tar.gz archive with the
// binary inside — we stream it through gzip+tar, extract only the
// `telemt` entry, and sha256-verify the archive against its sidecar
// so a mid-transfer corruption or supply-chain tampering fails
// loudly instead of silently landing a bad binary.
func (m *Manager) ensureBinary(ctx context.Context) error {
	if info, err := os.Stat(m.Paths.Binary); err == nil && info.Mode().IsRegular() {
		return nil
	}
	rawURL, err := DownloadURL(Version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	return m.fetchAndExtract(ctx, m.Paths.Binary, rawURL)
}

// fetchAndExtract downloads a tar.gz from rawURL into dst (as the
// `telemt` entry inside the archive), verifying the full archive
// bytes against the sha256 sidecar at `rawURL + ".sha256"` before
// writing the extracted file out. Failure modes are all hard errors:
//
//   - sidecar fetch error / non-2xx      → "fetch sha256"
//   - sidecar malformed                  → "sha256 sidecar"
//   - archive fetch error                → "fetch"
//   - hash mismatch                      → "sha256 mismatch"
//   - archive missing the telemt entry   → "tar: telemt entry missing"
//
// Mirrors amneziawg.Manager.fetchAndVerify but adds the tar.gz
// extraction step telemt's release format needs.
func (m *Manager) fetchAndExtract(ctx context.Context, dst, rawURL string) error {
	expected, err := m.fetchSHA256(ctx, rawURL+".sha256")
	if err != nil {
		return err
	}

	rc, err := m.Downloader.Get(ctx, rawURL)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", rawURL, err)
	}
	defer func() { _ = rc.Close() }()

	// Tee the archive bytes into the hasher so we verify the
	// exact wire content (not the extracted binary — a clever
	// attacker could repack).
	h := sha256.New()
	tee := io.TeeReader(rc, h)

	gz, err := gzip.NewReader(tee)
	if err != nil {
		return fmt.Errorf("gzip open %s: %w", rawURL, err)
	}
	defer func() { _ = gz.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read %s: %w", rawURL, err)
		}
		// Archive layout from upstream is a single flat entry
		// named `telemt`. Be strict: reject any other entry so a
		// compromised archive that adds attacker.sh somewhere
		// else in the tree does not silently land.
		name := filepath.Base(hdr.Name)
		if name != "telemt" {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("tar %s: telemt entry has unexpected typeflag %d", rawURL, hdr.Typeflag)
		}
		if err := writeFromReader(dst, tr, 0o755); err != nil {
			return err
		}
		found = true
		break
	}
	// Drain the rest so the tee sees the full archive (some tar
	// archives pad to 512-byte blocks after the last entry).
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("drain %s: %w", rawURL, err)
	}
	if !found {
		_ = os.Remove(dst)
		return fmt.Errorf("tar %s: telemt entry missing", rawURL)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		_ = os.Remove(dst)
		return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", rawURL, actual, expected)
	}
	return nil
}

// fetchSHA256 pulls a sha256 sidecar URL and returns the leading
// 64-hex digest. Shape matches amneziawg.parseSHA256Line: we accept
// both `<hex>  <name>` and `<hex> *<name>` formats that sha256sum(1)
// produces.
func (m *Manager) fetchSHA256(ctx context.Context, sumURL string) (string, error) {
	rc, err := m.Downloader.Get(ctx, sumURL)
	if err != nil {
		return "", fmt.Errorf("fetch sha256 %s: %w", sumURL, err)
	}
	sumBytes, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		return "", fmt.Errorf("read sha256 %s: %w", sumURL, err)
	}
	digest, err := parseSHA256Line(sumBytes)
	if err != nil {
		return "", fmt.Errorf("sha256 sidecar %s: %w", sumURL, err)
	}
	return digest, nil
}

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

// DownloadURL returns the telemt release-asset URL for the given
// host triple. telemt publishes per-arch tar.gz archives with both
// glibc (-gnu) and musl (-musl) variants. We pick musl for maximum
// portability — telemt's musl build is fully static and runs on any
// kernel ≥ 3.17, which covers every Debian/Ubuntu LTS we target and
// sidesteps glibc-ABI drift the gnu build would be subject to.
func DownloadURL(version, goos, goarch string) (string, error) {
	if goos != "linux" {
		return "", fmt.Errorf("unsupported GOOS %q (telemt ships linux only here)", goos)
	}
	asset, ok := linuxAsset[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported GOARCH %q for linux", goarch)
	}
	return fmt.Sprintf(
		"https://github.com/telemt/telemt/releases/download/%s/%s",
		url.PathEscape(version), asset,
	), nil
}

// linuxAsset maps Go arch names to upstream telemt release-asset
// names. Verified against
// https://api.github.com/repos/telemt/telemt/releases/latest.
var linuxAsset = map[string]string{
	"amd64": "telemt-x86_64-linux-musl.tar.gz",
	"arm64": "telemt-aarch64-linux-musl.tar.gz",
}

// writeFileAtomic creates or replaces dst with contents at mode
// using the temp-file + rename pattern. Mirrors the helper in the
// hysteria2/amneziawg packages — kept local to avoid a shared-utils
// package that every transport would end up importing.
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

// systemdUnitTemplate runs telemt as a dedicated `telemt` system
// user. CAP_NET_BIND_SERVICE is kept in case the operator moves the
// listen port to <1024; CAP_NET_ADMIN comes from upstream's
// recommended unit — telemt uses it for setsockopt tuning on some
// kernels. NoNewPrivileges hardens the dropping.
const systemdUnitTemplate = `[Unit]
Description=xray-aio managed MTProto Fake-TLS (telemt)
Documentation=https://github.com/telemt/telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{USER}}
Group={{USER}}
WorkingDirectory={{HOME}}
ExecStart={{BINARY}} {{CONFIG}}
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

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
