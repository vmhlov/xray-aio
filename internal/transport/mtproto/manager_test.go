package mtproto

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
		return io.NopCloser(bytes.NewReader(nil)), nil
	}
	p := f.bodies[f.idx]
	f.idx++
	return io.NopCloser(bytes.NewReader(p)), nil
}

// newFakeDL sequences (sidecar, archive) pairs in the order
// Manager.fetchAndExtract requests them. Mirrors
// amneziawg.newFakeDL but for the tar.gz + single-binary shape.
func newFakeDL(archives ...[]byte) *fakeDownloader {
	bodies := make([][]byte, 0, 2*len(archives))
	for _, a := range archives {
		bodies = append(bodies, sha256SidecarFor(a), a)
	}
	return &fakeDownloader{bodies: bodies}
}

func sha256SidecarFor(payload []byte) []byte {
	sum := sha256.Sum256(payload)
	return fmt.Appendf(nil, "%s  telemt-asset.tar.gz\n", hex.EncodeToString(sum[:]))
}

// makeArchive builds a gzip+tar archive with a single regular-file
// entry named `telemt` carrying `body`. This is the exact on-the-wire
// shape upstream releases publish — the tar stream has one file, no
// directory entries.
func makeArchive(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "telemt",
		Mode:     0o755,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

// makeArchiveNoTelemt is the adversarial archive: tar contains only
// an unrelated file. ensureBinary must report an error — not silently
// leave /usr/local/bin/telemt empty.
func makeArchiveNoTelemt(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "attacker",
		Mode:     0o755,
		Size:     4,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gz close: %v", err)
	}
	return buf.Bytes()
}

func newTestPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	p := Paths{
		Binary:    filepath.Join(root, "bin", "telemt"),
		ConfigDir: filepath.Join(root, "etc", "mtproto"),
		Config:    filepath.Join(root, "etc", "mtproto", "telemt.toml"),
		UnitFile:  filepath.Join(root, "etc", "systemd", "xray-aio-mtproto.service"),
		UnitName:  "xray-aio-mtproto.service",
		HomeDir:   filepath.Join(root, "opt", "telemt"),
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
		Domain: "vpn.example.com",
		Secret: "deadbeefcafebabedeadbeefcafebabe",
	}
}

func TestManagerInstall(t *testing.T) {
	paths := newTestPaths(t)
	body := []byte("\x7fELF fake telemt binary body")
	archive := makeArchive(t, body)
	runner := &fakeRunner{}
	dl := newFakeDL(archive)
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("extracted binary content mismatch: got %d bytes, want %d", len(got), len(body))
	}
	if info, _ := os.Stat(paths.Binary); info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("binary not executable: %v", info.Mode())
	}

	cfgBytes, err := os.ReadFile(paths.Config)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(cfgBytes), "deadbeefcafebabedeadbeefcafebabe") {
		t.Fatalf("config missing secret: %s", cfgBytes)
	}
	// Config carries the Fake-TLS secret. Must not be world-readable.
	if info, _ := os.Stat(paths.Config); info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("config readable by world: %v", info.Mode())
	}

	unit, err := os.ReadFile(paths.UnitFile)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	for _, want := range []string{
		paths.Binary,
		paths.Config,
		"User=telemt",
		"AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit missing %q; got:\n%s", want, unit)
		}
	}

	// The runner should have been driven through the full
	// daemon-reload → enable → restart dance, plus sysuser and
	// chown calls.
	wantSubcommands := []string{"daemon-reload", "enable", "restart"}
	for _, sub := range wantSubcommands {
		found := false
		for _, call := range runner.calls {
			if len(call) >= 2 && call[0] == "systemctl" && call[1] == sub {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("systemctl %s never invoked; calls=%v", sub, runner.calls)
		}
	}
}

func TestManagerInstallIdempotentWhenBinaryExists(t *testing.T) {
	paths := newTestPaths(t)
	// Pre-place a binary — ensureBinary must short-circuit and
	// the Downloader must not be touched.
	if err := os.WriteFile(paths.Binary, []byte("preexisting"), 0o755); err != nil {
		t.Fatalf("pre-place: %v", err)
	}
	runner := &fakeRunner{}
	dl := &fakeDownloader{err: errors.New("must not be called")}
	m := &Manager{Paths: paths, Runner: runner, Downloader: dl}

	if err := m.Install(context.Background(), validConfig()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, err := os.ReadFile(paths.Binary)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	if string(got) != "preexisting" {
		t.Errorf("binary overwritten: got %q", got)
	}
}

func TestManagerInstallSHA256Mismatch(t *testing.T) {
	paths := newTestPaths(t)
	archive := makeArchive(t, []byte("real body"))
	// Sidecar for a *different* archive — must cause fetchAndExtract
	// to remove the partial file and surface a "sha256 mismatch".
	wrongSum := sha256SidecarFor(makeArchive(t, []byte("attacker-supplied body")))
	dl := &fakeDownloader{bodies: [][]byte{wrongSum, archive}}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), validConfig())
	if err == nil {
		t.Fatalf("want sha256 mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("want 'sha256 mismatch' error, got: %v", err)
	}
	// Partial file must have been removed.
	if _, err := os.Stat(paths.Binary); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tampered binary should have been removed; stat err=%v", err)
	}
}

func TestManagerInstallMalformedSidecar(t *testing.T) {
	paths := newTestPaths(t)
	archive := makeArchive(t, []byte("real body"))
	dl := &fakeDownloader{bodies: [][]byte{[]byte("not hex at all"), archive}}
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), validConfig())
	if err == nil {
		t.Fatalf("want sidecar-parse error, got nil")
	}
	if !strings.Contains(err.Error(), "sha256 sidecar") && !strings.Contains(err.Error(), "expected 64-hex-char digest") {
		t.Errorf("want sidecar-parse error, got: %v", err)
	}
}

func TestManagerInstallArchiveMissingTelemt(t *testing.T) {
	paths := newTestPaths(t)
	archive := makeArchiveNoTelemt(t)
	dl := newFakeDL(archive)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), validConfig())
	if err == nil {
		t.Fatalf("want 'telemt entry missing' error, got nil")
	}
	if !strings.Contains(err.Error(), "telemt entry missing") {
		t.Errorf("want 'telemt entry missing', got: %v", err)
	}
}

func TestManagerInstallInvalidConfig(t *testing.T) {
	paths := newTestPaths(t)
	archive := makeArchive(t, []byte("body"))
	dl := newFakeDL(archive)
	m := &Manager{Paths: paths, Runner: &fakeRunner{}, Downloader: dl}

	err := m.Install(context.Background(), Config{Domain: "", Secret: "bad"})
	if err == nil {
		t.Fatalf("want config-validation error, got nil")
	}
	// Neither the binary nor the config should have been written.
	if _, err := os.Stat(paths.Config); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("config written despite invalid cfg")
	}
}

func TestManagerStatus(t *testing.T) {
	paths := newTestPaths(t)
	runner := &fakeRunner{out: []byte("active\n")}
	m := &Manager{Paths: paths, Runner: runner, Downloader: &fakeDownloader{}}
	active, raw, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !active || raw != "active" {
		t.Errorf("active=%v raw=%q", active, raw)
	}
}

func TestManagerUninstallIdempotent(t *testing.T) {
	paths := newTestPaths(t)
	runner := &fakeRunner{}
	m := &Manager{Paths: paths, Runner: runner, Downloader: &fakeDownloader{}}
	// Nothing exists yet — Uninstall must still succeed (idempotent).
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall on empty: %v", err)
	}
	// Now lay down the files and Uninstall again.
	for _, f := range []string{paths.Config, paths.UnitFile} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	for _, f := range []string{paths.Config, paths.UnitFile} {
		if _, err := os.Stat(f); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still present after Uninstall", f)
		}
	}
}

func TestDownloadURL(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         string
		wantErr      bool
	}{
		{"linux", "amd64", "https://github.com/telemt/telemt/releases/download/" + Version + "/telemt-x86_64-linux-musl.tar.gz", false},
		{"linux", "arm64", "https://github.com/telemt/telemt/releases/download/" + Version + "/telemt-aarch64-linux-musl.tar.gz", false},
		{"linux", "386", "", true},
		{"darwin", "amd64", "", true},
	}
	for _, tc := range cases {
		name := tc.goos + "/" + tc.goarch
		t.Run(name, func(t *testing.T) {
			got, err := DownloadURL(Version, tc.goos, tc.goarch)
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got URL %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DownloadURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("DownloadURL=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseSHA256Line(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"abc123" + strings.Repeat("f", 58) + "  asset\n", "abc123" + strings.Repeat("f", 58), false},
		{"abc123" + strings.Repeat("f", 58) + " *asset\n", "abc123" + strings.Repeat("f", 58), false},
		{"too short", "", true},
		{strings.Repeat("z", 64) + " asset", "", true}, // not hex
	}
	for i, tc := range cases {
		got, err := parseSHA256Line([]byte(tc.in))
		if tc.wantErr {
			if err == nil {
				t.Errorf("case %d: want error, got %q", i, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d: unexpected error: %v", i, err)
			continue
		}
		if got != tc.want {
			t.Errorf("case %d: got %q, want %q", i, got, tc.want)
		}
	}
}
