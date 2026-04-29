package xray

import (
	"archive/zip"
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

// makeXrayZip returns a zip archive matching the upstream layout —
// `xray` binary plus a couple of decoy files.
func makeXrayZip(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"geoip.dat", []byte("ip")},
		{"geosite.dat", []byte("site")},
		{"xray", payload},
		{"README.md", []byte("readme")},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		Binary:    filepath.Join(root, "bin", "xray"),
		ConfigDir: filepath.Join(root, "etc", "xray"),
		Config:    filepath.Join(root, "etc", "xray", "config.json"),
		UnitFile:  filepath.Join(root, "etc", "systemd", "xray-aio-xray.service"),
		UnitName:  "xray-aio-xray.service",
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
	payload := []byte("\x7fELF fake xray")
	runner := &fakeRunner{}
	dl := &fakeDownloader{body: makeXrayZip(t, payload)}
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	cfg := validConfig(t)
	if err := m.Install(context.Background(), cfg); err != nil {
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
	if !strings.Contains(string(cfgBytes), `"protocol": "vless"`) {
		t.Fatalf("config missing protocol: %s", cfgBytes)
	}
	if info, _ := os.Stat(paths.Config); info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("config readable by group/other: %v", info.Mode())
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, want := range []string{
		paths.Binary, paths.Config,
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"User=xray",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}

	wantCalls := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "xray-aio-xray.service"},
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
	if err := m.Install(context.Background(), validConfig(t)); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, _ := os.ReadFile(paths.Binary)
	if string(got) != "preexisting" {
		t.Fatalf("binary overwritten: %q", got)
	}
}

func TestManagerReloadRestarts(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.WriteFile(paths.Binary, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner}
	if err := m.Reload(context.Background(), validConfig(t)); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	want := []string{"systemctl", "restart", "xray-aio-xray.service"}
	if len(runner.calls) != 1 || !sliceEq(runner.calls[0], want) {
		t.Fatalf("calls=%v want %v", runner.calls, want)
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
	for _, p := range []string{paths.Config, paths.UnitFile} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, p := range []string{paths.Config, paths.UnitFile, paths.ConfigDir} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s not removed: %v", p, err)
		}
	}
	wantFirst := []string{"systemctl", "disable", "--now", "xray-aio-xray.service"}
	if len(runner.calls) == 0 || !sliceEq(runner.calls[0], wantFirst) {
		t.Fatalf("first call=%v want %v", runner.calls, wantFirst)
	}
}

func TestExtractXrayMissingBinary(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("README.md")
	_, _ = w.Write([]byte("hi"))
	_ = zw.Close()
	dst := filepath.Join(t.TempDir(), "xray")
	if err := extractXray(&buf, dst); err == nil {
		t.Fatal("expected error for archive without xray binary")
	}
}

func TestExtractXrayCorrupt(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "xray")
	if err := extractXray(bytes.NewReader([]byte("not a zip")), dst); err == nil {
		t.Fatal("expected error for non-zip input")
	}
}

func TestDownloadURL(t *testing.T) {
	cases := []struct {
		os, arch string
		want     string
		err      bool
	}{
		{"linux", "amd64", "https://github.com/XTLS/Xray-core/releases/download/v" + Version + "/Xray-linux-64.zip", false},
		{"linux", "arm64", "https://github.com/XTLS/Xray-core/releases/download/v" + Version + "/Xray-linux-arm64-v8a.zip", false},
		{"linux", "386", "https://github.com/XTLS/Xray-core/releases/download/v" + Version + "/Xray-linux-32.zip", false},
		{"linux", "riscv64", "", true},
		{"darwin", "amd64", "", true},
	}
	for _, tc := range cases {
		got, err := DownloadURL(Version, tc.os, tc.arch)
		if tc.err {
			if err == nil {
				t.Errorf("%s/%s: expected error", tc.os, tc.arch)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s/%s: %v", tc.os, tc.arch, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s/%s: got %q want %q", tc.os, tc.arch, got, tc.want)
		}
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
