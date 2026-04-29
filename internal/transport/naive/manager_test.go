package naive

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
		Binary:    filepath.Join(root, "bin", "caddy-naive"),
		ConfigDir: filepath.Join(root, "etc", "naive"),
		Caddyfile: filepath.Join(root, "etc", "naive", "Caddyfile"),
		SiteRoot:  filepath.Join(root, "var", "lib", "naive-selfsteal"),
		UnitFile:  filepath.Join(root, "etc", "systemd", "xray-aio-naive.service"),
		UnitName:  "xray-aio-naive.service",
	}
	for _, d := range []string{
		filepath.Dir(p.Binary), p.ConfigDir,
		filepath.Dir(p.UnitFile), p.SiteRoot,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestManagerInstall(t *testing.T) {
	paths := newTestPaths(t)
	binPayload := []byte("\x7fELF fake caddy")
	runner := &fakeRunner{}
	dl := &fakeDownloader{body: binPayload}
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), goodOpts()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, binPayload) {
		t.Fatalf("binary content mismatch")
	}
	if info, _ := os.Stat(paths.Binary); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("binary not executable: %v", info.Mode())
	}

	cf, err := os.ReadFile(paths.Caddyfile)
	if err != nil {
		t.Fatalf("read Caddyfile: %v", err)
	}
	for _, want := range []string{
		"basic_auth alice s3cret",
		"probe_resistance secret-host.example",
		"hide_ip",
	} {
		if !strings.Contains(string(cf), want) {
			t.Fatalf("Caddyfile missing %q:\n%s", want, cf)
		}
	}
	if info, _ := os.Stat(paths.Caddyfile); info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("Caddyfile readable by group/other: %v", info.Mode())
	}

	idx, err := os.ReadFile(filepath.Join(paths.SiteRoot, "index.html"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if !bytes.Contains(idx, []byte("<html")) {
		t.Fatalf("index.html doesn't look like HTML: %s", idx[:min(80, len(idx))])
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, want := range []string{
		paths.Binary, paths.Caddyfile,
		"RuntimeDirectory=xray-aio",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"ExecReload=",
		"ProtectSystem=full",
	} {
		if !strings.Contains(string(unit), want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}

	want := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "--now", "xray-aio-naive.service"},
	}
	if !equalCalls(runner.calls, want) {
		t.Fatalf("calls=%v want %v", runner.calls, want)
	}
}

func TestManagerInstallSkipsExistingBinary(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.WriteFile(paths.Binary, []byte("preexisting"), 0o755); err != nil {
		t.Fatal(err)
	}
	dl := &fakeDownloader{err: errors.New("must not be called")}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}
	if err := m.Install(context.Background(), goodOpts()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, _ := os.ReadFile(paths.Binary)
	if string(got) != "preexisting" {
		t.Fatalf("binary overwritten: %q", got)
	}
}

func TestManagerInstallPreservesOperatorIndex(t *testing.T) {
	paths := newTestPaths(t)
	custom := []byte("<!doctype html><title>operator's page</title>")
	if err := os.WriteFile(filepath.Join(paths.SiteRoot, "index.html"), custom, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Binary, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}}
	if err := m.Install(context.Background(), goodOpts()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, _ := os.ReadFile(filepath.Join(paths.SiteRoot, "index.html"))
	if !bytes.Equal(got, custom) {
		t.Fatalf("operator index overwritten:\n got %q\nwant %q", got, custom)
	}
}

func TestManagerReloadCallsSystemdReload(t *testing.T) {
	paths := newTestPaths(t)
	if err := os.WriteFile(paths.Binary, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner}
	if err := m.Reload(context.Background(), goodOpts()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	want := []string{"systemctl", "reload", "xray-aio-naive.service"}
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
	if len(runner.calls) == 0 || runner.calls[0][0] != "systemctl" || runner.calls[0][1] != "disable" {
		t.Fatalf("first call=%v", runner.calls)
	}
}

func TestDefaultBuildURL(t *testing.T) {
	cases := []struct {
		os, arch string
		want     string
		err      bool
	}{
		{"linux", "amd64", "https://caddyserver.com/api/download?arch=amd64&os=linux&p=github.com%2Fcaddyserver%2Fforwardproxy", false},
		{"linux", "arm64", "https://caddyserver.com/api/download?arch=arm64&os=linux&p=github.com%2Fcaddyserver%2Fforwardproxy", false},
		{"linux", "riscv64", "", true},
		{"darwin", "amd64", "", true},
	}
	for _, tc := range cases {
		got, err := DefaultBuildURL(tc.os, tc.arch)
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
			t.Errorf("%s/%s:\n got %q\nwant %q", tc.os, tc.arch, got, tc.want)
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
