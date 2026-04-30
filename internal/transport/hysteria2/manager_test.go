package hysteria2

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
	body []byte
	err  error
}

func (f *fakeDownloader) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(bytes.NewReader(f.body)), nil
}

func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		Binary:    filepath.Join(root, "bin", "hysteria"),
		ConfigDir: filepath.Join(root, "etc", "hysteria2"),
		Config:    filepath.Join(root, "etc", "hysteria2", "config.yaml"),
		UnitFile:  filepath.Join(root, "etc", "systemd", "xray-aio-hysteria2.service"),
		UnitName:  "xray-aio-hysteria2.service",
	}
	for _, d := range []string{filepath.Dir(p.Binary), p.ConfigDir, filepath.Dir(p.UnitFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func validConfig() Config {
	return Config{
		Domain:   "vpn.example.com",
		Password: "topsecret",
	}
}

func TestManagerInstall(t *testing.T) {
	paths := newTestPaths(t)
	payload := []byte("\x7fELF fake hysteria binary body")
	runner := &fakeRunner{}
	dl := &fakeDownloader{body: payload}
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("binary content mismatch")
	}
	if info, _ := os.Stat(paths.Binary); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("binary not executable: %v", info.Mode())
	}

	cfgBytes, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfgBytes), "password: topsecret") {
		t.Fatalf("config missing password: %s", cfgBytes)
	}
	// Config carries the auth password. Must not be world-readable.
	if info, _ := os.Stat(paths.Config); info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("config readable by world: %v", info.Mode())
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, want := range []string{
		paths.Binary, paths.Config,
		"User=caddy",
		"Group=caddy",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"After=network-online.target xray-aio-naive.service",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit missing %q\n%s", want, unit)
		}
	}

	// At minimum: getent (sysuser probe), chown, daemon-reload,
	// enable+start. Deeper introspection lives in dedicated tests.
	gotCmds := commandSummary(runner)
	for _, want := range []string{
		"getent passwd caddy",
		"daemon-reload",
		"enable --now xray-aio-hysteria2.service",
	} {
		if !strings.Contains(gotCmds, want) {
			t.Errorf("expected command %q in:\n%s", want, gotCmds)
		}
	}
}

func TestManagerInstallSkipsBinaryWhenPresent(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.WriteFile(paths.Binary, []byte("alreadyhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	dl := &fakeDownloader{err: errors.New("must not be called")}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}
	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alreadyhere" {
		t.Errorf("Install overwrote pre-existing binary: %q", got)
	}
}

func TestManagerInstallRejectsBadConfig(t *testing.T) {
	paths := newTestPaths(t)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: &fakeDownloader{body: []byte("x")}}
	err := m.Install(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error from empty config")
	}
}

func TestManagerLifecycleCmds(t *testing.T) {
	paths := newTestPaths(t)
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner, Downloader: &fakeDownloader{body: []byte("bin")}}

	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := commandSummary(runner)
	for _, want := range []string{
		"systemctl start xray-aio-hysteria2.service",
		"systemctl stop xray-aio-hysteria2.service",
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
	m := &Manager{Paths: paths, Runner: runner, Downloader: &fakeDownloader{body: []byte("x")}}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, p := range []string{paths.Config, paths.UnitFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("file still present: %s err=%v", p, err)
		}
	}
}

func TestDownloadURL(t *testing.T) {
	got, err := DownloadURL("2.8.2", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://github.com/apernet/hysteria/releases/download/app%2Fv2.8.2/hysteria-linux-amd64"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestDownloadURLRejectsUnsupportedTriples(t *testing.T) {
	if _, err := DownloadURL("2.8.2", "darwin", "amd64"); err == nil {
		t.Errorf("expected error for darwin")
	}
	if _, err := DownloadURL("2.8.2", "linux", "ppc64"); err == nil {
		t.Errorf("expected error for ppc64")
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
