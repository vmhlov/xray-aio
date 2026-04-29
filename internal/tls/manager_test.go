package tls

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records every Run call and returns canned values.
type fakeRunner struct {
	calls [][]string
	out   []byte
	err   error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

// fakeDownloader returns canned bytes for any URL.
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

// makeCaddyTarball returns a gzipped tar containing a single fake
// 'caddy' executable file with the given payload.
func makeCaddyTarball(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"README.md", []byte("readme")},
		{"caddy", payload},
	} {
		hdr := &tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.data))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		Binary:       filepath.Join(root, "bin", "caddy"),
		ConfigDir:    filepath.Join(root, "etc", "caddy"),
		Caddyfile:    filepath.Join(root, "etc", "caddy", "Caddyfile"),
		SelfStealDir: filepath.Join(root, "var", "selfsteal"),
		UnitFile:     filepath.Join(root, "etc", "systemd", "xray-aio-caddy.service"),
		UnitName:     "xray-aio-caddy.service",
	}
	for _, d := range []string{filepath.Dir(p.Binary), p.ConfigDir, filepath.Dir(p.UnitFile)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestManagerInstall(t *testing.T) {
	paths := newTestPaths(t)
	caddyPayload := []byte("\x7fELF fake binary")
	runner := &fakeRunner{}
	dl := &fakeDownloader{body: makeCaddyTarball(t, caddyPayload)}
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), Options{Domain: "example.com", Email: "ops@example.com"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, caddyPayload) {
		t.Fatalf("binary content mismatch: got %q", got)
	}
	if info, _ := os.Stat(paths.Binary); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("binary not executable: %v", info.Mode())
	}

	cf, err := os.ReadFile(paths.Caddyfile)
	if err != nil {
		t.Fatalf("read caddyfile: %v", err)
	}
	if !strings.Contains(string(cf), "example.com") {
		t.Fatalf("caddyfile missing domain: %s", cf)
	}

	idx := filepath.Join(paths.SelfStealDir, "index.html")
	if b, err := os.ReadFile(idx); err != nil {
		t.Fatalf("read selfsteal: %v", err)
	} else if !strings.Contains(string(b), "<!doctype html>") {
		t.Fatalf("selfsteal not html: %s", b)
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	if !strings.Contains(string(unit), paths.Binary) || !strings.Contains(string(unit), paths.Caddyfile) {
		t.Fatalf("unit missing path substitutions: %s", unit)
	}

	wantCalls := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "xray-aio-caddy.service"},
	}
	if !equalCalls(runner.calls, wantCalls) {
		t.Fatalf("calls=%v want %v", runner.calls, wantCalls)
	}
}

func TestManagerInstallSkipsExistingBinary(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.WriteFile(paths.Binary, []byte("preexisting"), 0o755); err != nil {
		t.Fatal(err)
	}
	dl := &fakeDownloader{err: errors.New("must not be called")}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}
	if err := m.Install(context.Background(), Options{Domain: "example.com"}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, _ := os.ReadFile(paths.Binary)
	if string(got) != "preexisting" {
		t.Fatalf("binary overwritten: %q", got)
	}
}

func TestManagerInstallPreservesOperatorSelfStealPage(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.MkdirAll(paths.SelfStealDir, 0o755); err != nil {
		t.Fatal(err)
	}
	custom := []byte("<!doctype html><html>operator page</html>")
	idx := filepath.Join(paths.SelfStealDir, "index.html")
	if err := os.WriteFile(idx, custom, 0o644); err != nil {
		t.Fatal(err)
	}
	dl := &fakeDownloader{body: makeCaddyTarball(t, []byte("fake"))}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}
	if err := m.Install(context.Background(), Options{Domain: "example.com"}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, _ := os.ReadFile(idx)
	if !bytes.Equal(got, custom) {
		t.Fatalf("operator page was overwritten:\nwant %q\ngot  %q", custom, got)
	}
}

func TestManagerStatus(t *testing.T) {
	paths := newTestPaths(t)
	t.Run("active", func(t *testing.T) {
		m := &Manager{Paths: paths, Runner: &fakeRunner{out: []byte("active\n")}}
		ok, raw, err := m.Status(context.Background())
		if err != nil || !ok || raw != "active" {
			t.Fatalf("ok=%v raw=%q err=%v", ok, raw, err)
		}
	})
	t.Run("inactive", func(t *testing.T) {
		m := &Manager{Paths: paths, Runner: &fakeRunner{out: []byte("inactive\n")}}
		ok, raw, err := m.Status(context.Background())
		if err != nil || ok || raw != "inactive" {
			t.Fatalf("ok=%v raw=%q err=%v", ok, raw, err)
		}
	})
}

func TestManagerUninstall(t *testing.T) {
	paths := newTestPaths(t)
	for _, p := range []string{paths.Caddyfile, paths.UnitFile} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, p := range []string{paths.Caddyfile, paths.UnitFile, paths.ConfigDir} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s not removed: %v", p, err)
		}
	}
	wantFirst := []string{"systemctl", "disable", "--now", "xray-aio-caddy.service"}
	if len(runner.calls) == 0 || !sliceEq(runner.calls[0], wantFirst) {
		t.Fatalf("first call=%v want %v", runner.calls, wantFirst)
	}
}

func TestExtractCaddyMissingBinary(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "README.md", Mode: 0o644, Size: 3}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hi\n")); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	dst := filepath.Join(t.TempDir(), "caddy")
	if err := extractCaddy(&buf, dst); err == nil {
		t.Fatal("expected error for tarball without caddy binary")
	}
}

func TestCaddyDownloadURL(t *testing.T) {
	got := caddyDownloadURL("2.8.4", "linux", "amd64")
	want := "https://github.com/caddyserver/caddy/releases/download/v2.8.4/caddy_2.8.4_linux_amd64.tar.gz"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func equalCalls(got, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !sliceEq(got[i], want[i]) {
			return false
		}
	}
	return true
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
