package preflight

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRun(t *testing.T) {
	r, err := Run(context.Background())
	// On the dev / CI machine some checks will produce warnings or
	// even errors (port 80 may need root, IPv6 may be missing) — we
	// only assert that Run returns a populated Result.
	if len(r.Checks) == 0 {
		t.Fatal("no checks executed")
	}
	if r.OS == "" || r.Arch == "" {
		t.Fatal("OS/Arch not populated")
	}
	t.Logf("HasErrors=%v HasWarnings=%v err=%v", r.HasErrors(), r.HasWarnings(), err)
	for _, c := range r.Checks {
		t.Logf("[%s] %s — %s", c.Status, c.Name, c.Message)
	}
}

func TestResultFlags(t *testing.T) {
	cases := []struct {
		name              string
		checks            []Check
		wantErr, wantWarn bool
	}{
		{"all-ok", []Check{{Name: "a", Status: StatusOK}}, false, false},
		{"warn", []Check{{Name: "a", Status: StatusOK}, {Name: "b", Status: StatusWarn}}, false, true},
		{"err", []Check{{Name: "a", Status: StatusError}}, true, false},
		{"err+warn", []Check{{Name: "a", Status: StatusError}, {Name: "b", Status: StatusWarn}}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Result{Checks: tc.checks}
			if r.HasErrors() != tc.wantErr {
				t.Fatalf("HasErrors=%v want %v", r.HasErrors(), tc.wantErr)
			}
			if r.HasWarnings() != tc.wantWarn {
				t.Fatalf("HasWarnings=%v want %v", r.HasWarnings(), tc.wantWarn)
			}
		})
	}
}

func TestReadOSRelease(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte(`PRETTY_NAME="Test Linux 1.0"
ID=test
VERSION_ID=1.0
`), 0o644); err != nil {
		t.Fatal(err)
	}
	id, pretty, err := readOSRelease(p)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if id != "test" {
		t.Fatalf("id=%q", id)
	}
	if pretty != "Test Linux 1.0" {
		t.Fatalf("pretty=%q", pretty)
	}
}

func TestReadOSReleaseMissing(t *testing.T) {
	if _, _, err := readOSRelease(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestRunWithAmneziaWGAddsAWGChecks(t *testing.T) {
	// RunWith with AmneziaWGListenPort > 0 must extend the standard
	// suite with the two AWG-specific checks. We point DevNetTUNPath
	// at a missing file so the suite reliably surfaces an error
	// without depending on whether /dev/net/tun exists in CI.
	port := pickFreeUDPPort(t)
	r, err := RunWith(context.Background(), Options{
		AmneziaWGListenPort: port,
		DevNetTUNPath:       filepath.Join(t.TempDir(), "no-tun-here"),
	})
	if err == nil {
		t.Fatal("expected err: dev-net-tun should fail on missing path")
	}
	var sawAWGUDP, sawTUN bool
	for _, c := range r.Checks {
		switch c.Name {
		case "amneziawg-udp":
			sawAWGUDP = true
			if c.Status != StatusOK {
				t.Errorf("amneziawg-udp on a free port: status=%s msg=%q", c.Status, c.Message)
			}
		case "dev-net-tun":
			sawTUN = true
			if c.Status != StatusError {
				t.Errorf("dev-net-tun on missing path: status=%s msg=%q; want error", c.Status, c.Message)
			}
		}
	}
	if !sawAWGUDP {
		t.Error("RunWith did not include amneziawg-udp check")
	}
	if !sawTUN {
		t.Error("RunWith did not include dev-net-tun check")
	}
}

func TestRunWithoutAmneziaWGSkipsAWGChecks(t *testing.T) {
	// Zero-value Options must NOT add AWG checks — the home-stealth
	// and home-mobile profiles do not need them and should not see
	// spurious errors when /dev/net/tun is absent on a build host.
	r, err := RunWith(context.Background(), Options{})
	_ = err
	for _, c := range r.Checks {
		if c.Name == "amneziawg-udp" || c.Name == "dev-net-tun" {
			t.Errorf("Options{} produced AWG check %q; want only the standard suite", c.Name)
		}
	}
}

func TestParseKernelVersion(t *testing.T) {
	cases := []struct {
		in               string
		wantMaj, wantMin int
	}{
		{"6.8.0-50-generic", 6, 8},
		{"5.4.0", 5, 4},
		{"5.4", 5, 4},
		{"4.15.0-200-generic", 4, 15},
		{"garbage", 0, 0},
		{"", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			maj, min := parseKernelVersion(tc.in)
			if maj != tc.wantMaj || min != tc.wantMin {
				t.Fatalf("got (%d,%d) want (%d,%d)", maj, min, tc.wantMaj, tc.wantMin)
			}
		})
	}
}
