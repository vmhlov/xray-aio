package amneziawg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls [][]string
	out   []byte
	err   error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

type fakeDownloader struct {
	bodies [][]byte
	idx    int
	err    error
}

func (f *fakeDownloader) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.idx >= len(f.bodies) {
		// Return empty body for any unscripted call so tests that
		// don't care about the precise number of fetches still get
		// past ensureBinaries (where they'd then trip the sha256
		// sidecar parser — which is the contract we want).
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	p := f.bodies[f.idx]
	f.idx++
	return io.NopCloser(bytes.NewReader(p)), nil
}

// newFakeDL builds a sequential fake whose response stream alternates
// the auto-derived sha256 sidecar and the payload itself, in the
// order the production [Manager.fetchAndVerify] requests them. So a
// caller passing two binary payloads gets four scripted bodies:
// (sum1, payload1, sum2, payload2). This matches the on-the-wire
// contract of the release workflow that PR #29 lands.
func newFakeDL(payloads ...[]byte) *fakeDownloader {
	bodies := make([][]byte, 0, 2*len(payloads))
	for _, p := range payloads {
		bodies = append(bodies, sha256SidecarFor(p), p)
	}
	return &fakeDownloader{bodies: bodies}
}

// newRawFakeDL is the escape hatch for adversarial tests that need
// to inject a sidecar with a deliberately wrong / malformed digest;
// payloads are returned in order without any auto-derivation.
func newRawFakeDL(payloads ...[]byte) *fakeDownloader {
	return &fakeDownloader{bodies: payloads}
}

// sha256SidecarFor returns the bytes the release workflow's
// `sha256sum` step would write for payload — "<hex>  asset\n".
func sha256SidecarFor(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return []byte(fmt.Sprintf("%s  asset\n", hex.EncodeToString(sum[:])))
}

func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		BinaryDaemon: filepath.Join(root, "bin", "amneziawg-go"),
		BinaryTool:   filepath.Join(root, "bin", "awg"),
		ConfigDir:    filepath.Join(root, "etc", "amneziawg"),
		Config:       filepath.Join(root, "etc", "amneziawg", "awg0.conf"),
		UnitFile:     filepath.Join(root, "etc", "systemd", "xray-aio-amneziawg.service"),
		UnitName:     "xray-aio-amneziawg.service",
	}
	for _, d := range []string{filepath.Dir(p.BinaryDaemon), p.ConfigDir, filepath.Dir(p.UnitFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func validConfig() Config {
	return Config{
		PrivateKey:    "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey: "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		Obfuscation:   goldObfuscation(),
	}
}

func TestManagerInstall(t *testing.T) {
	paths := newTestPaths(t)
	daemonPayload := []byte("\x7fELF fake amneziawg-go body")
	toolPayload := []byte("\x7fELF fake awg body")
	runner := &fakeRunner{}
	dl := newFakeDL(daemonPayload, toolPayload)
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	gotDaemon, err := os.ReadFile(paths.BinaryDaemon)
	if err != nil {
		t.Fatalf("read daemon: %v", err)
	}
	if !bytes.Equal(gotDaemon, daemonPayload) {
		t.Fatalf("daemon content mismatch")
	}
	gotTool, err := os.ReadFile(paths.BinaryTool)
	if err != nil {
		t.Fatalf("read tool: %v", err)
	}
	if !bytes.Equal(gotTool, toolPayload) {
		t.Fatalf("tool content mismatch")
	}
	for _, p := range []string{paths.BinaryDaemon, paths.BinaryTool} {
		if info, _ := os.Stat(p); info.Mode().Perm()&0o100 == 0 {
			t.Fatalf("%s not executable: %v", p, info.Mode())
		}
	}

	cfgBytes, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfgBytes), "PrivateKey = MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=") {
		t.Fatalf("config missing PrivateKey line:\n%s", cfgBytes)
	}
	// awg0.conf carries the server private key. Must not be
	// world- or group-readable.
	if info, _ := os.Stat(paths.Config); info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("awg0.conf permissive: %v", info.Mode())
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, want := range []string{
		paths.BinaryDaemon, paths.BinaryTool, paths.Config,
		"AmbientCapabilities=CAP_NET_ADMIN",
		"After=network-online.target",
		"setconf awg0",
		// The setconf hook is wrapped in a wait loop on the
		// amneziawg-go UAPI socket, because Type=simple makes
		// systemd run ExecStartPost before the daemon has had
		// time to bind /var/run/amneziawg/awg0.sock. Asserting
		// both the wait body and the socket path prevents a
		// future refactor from silently regressing the race
		// fix back into a flaky "Protocol not supported"
		// failure.
		"test -S " + uapiSocketPath,
		"timeout waiting for " + uapiSocketPath,
		// `ip addr add <SERVER_ADDR>` is the wg-quick-equivalent
		// hop that `awg setconf` cannot do for us, since it
		// rejects wg-quick directives. validConfig() leaves
		// ServerAddress empty, so DefaultServerAddress is what
		// the unit must end up referencing.
		"ip addr add " + DefaultServerAddress + " dev awg0",
		"ip link set up dev awg0",
		"ip link del awg0",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit missing %q\n%s", want, unit)
		}
	}

	gotCmds := commandSummary(runner)
	for _, want := range []string{
		"chown root:root",
		"daemon-reload",
		"enable xray-aio-amneziawg.service",
		"restart xray-aio-amneziawg.service",
	} {
		if !strings.Contains(gotCmds, want) {
			t.Errorf("expected command %q in:\n%s", want, gotCmds)
		}
	}
}

func TestManagerInstallSkipsBinariesWhenPresent(t *testing.T) {
	paths := newTestPaths(t)
	for _, p := range []string{paths.BinaryDaemon, paths.BinaryTool} {
		if err := os.WriteFile(p, []byte("alreadyhere"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dl := &fakeDownloader{err: errors.New("must not be called")}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}
	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, p := range []string{paths.BinaryDaemon, paths.BinaryTool} {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "alreadyhere" {
			t.Errorf("Install overwrote pre-existing binary at %s: %q", p, got)
		}
	}
}

func TestManagerInstallRejectsBadConfig(t *testing.T) {
	paths := newTestPaths(t)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: newFakeDL([]byte("x"), []byte("y"))}
	err := m.Install(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error from empty config")
	}
}

func TestManagerLifecycleCmds(t *testing.T) {
	paths := newTestPaths(t)
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner, Downloader: newFakeDL([]byte("d"), []byte("t"))}

	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := commandSummary(runner)
	for _, want := range []string{
		"systemctl start xray-aio-amneziawg.service",
		"systemctl stop xray-aio-amneziawg.service",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q\n%s", want, got)
		}
	}
}

func TestManagerUninstallRemovesArtifacts(t *testing.T) {
	paths := newTestPaths(t)
	for _, p := range []string{paths.Config, paths.UnitFile} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner, Downloader: newFakeDL([]byte("x"))}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, p := range []string{paths.Config, paths.UnitFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("file still present: %s err=%v", p, err)
		}
	}
	// Uninstall should also try to tear down the awg0 link
	// belt-and-suspenders style — we don't fail if the link is
	// gone, but the command should have been issued at least once.
	got := commandSummary(runner)
	if !strings.Contains(got, "ip link del dev awg0") {
		t.Errorf("expected `ip link del dev awg0` in uninstall, got:\n%s", got)
	}
}

func TestManagerReloadRewritesConfigAndRestarts(t *testing.T) {
	paths := newTestPaths(t)
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner, Downloader: newFakeDL()}
	cfg := validConfig()
	cfg.ListenPort = 51111
	if err := m.Reload(context.Background(), cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "ListenPort = 51111") {
		t.Errorf("Reload didn't rewrite config: %s", got)
	}
	cmds := commandSummary(runner)
	if !strings.Contains(cmds, "systemctl restart xray-aio-amneziawg.service") {
		t.Errorf("Reload should restart the unit, got:\n%s", cmds)
	}
}

func TestDaemonDownloadURL(t *testing.T) {
	got, err := DaemonDownloadURL("0.2.17", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/vmhlov/xray-aio/releases/download/amneziawg-go-v0.2.17/amneziawg-go-linux-amd64"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestDaemonDownloadURLArm64(t *testing.T) {
	got, err := DaemonDownloadURL("0.2.17", "linux", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "amneziawg-go-linux-arm64") {
		t.Errorf("expected arm64 asset, got %q", got)
	}
}

func TestDownloadURLRejectsUnsupportedTriples(t *testing.T) {
	if _, err := DaemonDownloadURL("0.2.17", "darwin", "amd64"); err == nil {
		t.Errorf("expected error for darwin")
	}
	if _, err := DaemonDownloadURL("0.2.17", "linux", "ppc64"); err == nil {
		t.Errorf("expected error for ppc64")
	}
	if _, err := ToolDownloadURL("1.0.20260223", "darwin", "amd64"); err == nil {
		t.Errorf("expected error for darwin tool")
	}
}

func TestToolDownloadURL(t *testing.T) {
	got, err := ToolDownloadURL("1.0.20260223", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "awg-linux-amd64") {
		t.Errorf("expected awg amd64 asset, got %q", got)
	}
	if !strings.Contains(got, "amneziawg-tools-v1.0.20260223") {
		t.Errorf("expected tools tag in URL, got %q", got)
	}
}

func TestManagerInstallRejectsSHA256Mismatch(t *testing.T) {
	// The release workflow uploads `<binary>` and `<binary>.sha256`
	// side-by-side. If the .sha256 sidecar disagrees with the
	// streamed body's hash, fetchAndVerify must remove the
	// half-written file and abort \u2014 not silently install a binary
	// whose integrity we cannot vouch for.
	paths := newTestPaths(t)
	daemonPayload := []byte("\x7fELF fake amneziawg-go body")
	// Sidecar advertises the digest of a DIFFERENT payload. Pin
	// the mismatch to a non-matching but well-formed 64-hex value
	// so we exercise the hash compare, not the parser.
	wrongSum := sha256SidecarFor([]byte("not the real payload"))
	dl := newRawFakeDL(wrongSum, daemonPayload)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), validConfig())
	if err == nil {
		t.Fatal("expected error from sha256 mismatch")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("error %q; want it to mention `sha256 mismatch`", err)
	}
	if _, statErr := os.Stat(paths.BinaryDaemon); !os.IsNotExist(statErr) {
		t.Errorf("daemon binary still on disk after mismatch: stat err=%v", statErr)
	}
}

func TestManagerInstallRejectsMalformedSHA256Sidecar(t *testing.T) {
	// A sidecar that does not start with 64 hex chars is treated
	// as a hard error \u2014 we don't fall back to "install
	// unverified". Common cause would be a 404 page body picked up
	// by mistake (the release asset path was wrong) or a
	// transport-truncated download.
	paths := newTestPaths(t)
	daemonPayload := []byte("\x7fELF fake amneziawg-go body")
	dl := newRawFakeDL([]byte("<html>404 Not Found</html>\n"), daemonPayload)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), validConfig())
	if err == nil {
		t.Fatal("expected error from malformed sidecar")
	}
	if !strings.Contains(err.Error(), "sha256 sidecar") {
		t.Errorf("error %q; want it to mention `sha256 sidecar`", err)
	}
	if _, statErr := os.Stat(paths.BinaryDaemon); !os.IsNotExist(statErr) {
		t.Errorf("daemon binary present after malformed-sidecar reject: stat err=%v", statErr)
	}
}

func TestManagerInstallSHA256ValidInstallsBinary(t *testing.T) {
	// Happy path pin: the auto-derived sidecar matches the
	// payload, fetchAndVerify completes, and both binaries land
	// on disk with mode 0755 and the exact bytes we scripted.
	// This is the contract the live release workflow guarantees.
	paths := newTestPaths(t)
	daemonPayload := []byte("\x7fELF fake amneziawg-go body sha256-verified")
	toolPayload := []byte("\x7fELF fake awg body sha256-verified")
	dl := newFakeDL(daemonPayload, toolPayload)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	gotDaemon, err := os.ReadFile(paths.BinaryDaemon)
	if err != nil {
		t.Fatalf("read daemon: %v", err)
	}
	if !bytes.Equal(gotDaemon, daemonPayload) {
		t.Errorf("daemon content mismatch: got %q, want %q", gotDaemon, daemonPayload)
	}
	gotTool, err := os.ReadFile(paths.BinaryTool)
	if err != nil {
		t.Fatalf("read tool: %v", err)
	}
	if !bytes.Equal(gotTool, toolPayload) {
		t.Errorf("tool content mismatch: got %q, want %q", gotTool, toolPayload)
	}
	for _, p := range []string{paths.BinaryDaemon, paths.BinaryTool} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Errorf("%s mode=%v; want 0755", p, info.Mode().Perm())
		}
	}
}

func TestParseSHA256LineAcceptsBothSha256SumFormats(t *testing.T) {
	// `sha256sum -b file` writes "<hex> *file"; the default mode
	// writes "<hex>  file" (two spaces). Pin both as accepted, plus
	// a header-style file with a trailing newline. The parser
	// must reject anything whose first whitespace-delimited
	// token is not exactly 64 hex chars.
	hex64 := strings.Repeat("a", 64)
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"binary-mode", hex64 + "  amneziawg-go-linux-amd64\n", hex64, false},
		{"text-mode", hex64 + " *amneziawg-go-linux-amd64\n", hex64, false},
		{"no-filename", hex64 + "\n", hex64, false},
		{"trailing-whitespace", "  " + hex64 + "  \n", hex64, false},
		{"too-short", strings.Repeat("a", 63) + "  asset\n", "", true},
		{"too-long", strings.Repeat("a", 65) + "  asset\n", "", true},
		{"non-hex", strings.Repeat("z", 64) + "  asset\n", "", true},
		{"html-404", "<html>404 Not Found</html>\n", "", true},
		{"empty", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSHA256Line([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func commandSummary(r *fakeRunner) string {
	var b strings.Builder
	for _, c := range r.calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
