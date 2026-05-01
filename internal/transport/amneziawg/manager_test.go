package amneziawg

import (
	"bytes"
	"context"
	"errors"
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
	bodies []*bytes.Reader
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
		// past ensureBinaries.
		return io.NopCloser(bytes.NewReader([]byte{})), nil
	}
	rc := io.NopCloser(f.bodies[f.idx])
	f.idx++
	return rc, nil
}

func newFakeDL(payloads ...[]byte) *fakeDownloader {
	rs := make([]*bytes.Reader, len(payloads))
	for i, p := range payloads {
		rs[i] = bytes.NewReader(p)
	}
	return &fakeDownloader{bodies: rs}
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

func commandSummary(r *fakeRunner) string {
	var b strings.Builder
	for _, c := range r.calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
