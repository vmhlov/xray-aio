package xray

import (
	"context"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/vmhlov/xray-aio/internal/transport"
)

func TestRegistration(t *testing.T) {
	tr, err := transport.Get(Name)
	if err != nil {
		t.Fatalf("Get(%q): %v", Name, err)
	}
	if tr.Name() != Name {
		t.Fatalf("Name() = %q, want %q", tr.Name(), Name)
	}
}

func TestConfigFromOptionsMinimal(t *testing.T) {
	opts := transport.Options{
		Domain: "example.com",
		Extra: map[string]any{
			"xray.uuid":        "deadbeef-1234-4567-89ab-0123456789ab",
			"xray.private_key": "uPRDuVscbHiK4N0wkgAcXSiPCnMltYWQs7H8w8q7eFw",
			"xray.public_key":  "kqkdvDhbE0c4mSMtRr_4l8m4Mb1iZ6Sxg2Tr9hJqW2g",
			"xray.short_ids":   []string{"deadbeef"},
		},
	}
	cfg, err := configFromOptions(opts)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.Domain != "example.com" {
		t.Errorf("Domain: %q", cfg.Domain)
	}
	if cfg.Dest != "127.0.0.1:8443" {
		t.Errorf("Dest default: %q", cfg.Dest)
	}
	if cfg.ListenPort != DefaultListenPort {
		t.Errorf("ListenPort default: %d", cfg.ListenPort)
	}
	if cfg.Mode != ModeVision {
		t.Errorf("Mode default: %q", cfg.Mode)
	}
	if !reflect.DeepEqual(cfg.ShortIDs, []string{"deadbeef"}) {
		t.Errorf("ShortIDs: %v", cfg.ShortIDs)
	}
}

func TestConfigFromOptionsAcceptsJSONShape(t *testing.T) {
	// Simulates state.json round-trip: ints become float64, []string
	// becomes []any.
	opts := transport.Options{
		Domain: "example.com",
		Extra: map[string]any{
			"xray.uuid":        "deadbeef-1234-4567-89ab-0123456789ab",
			"xray.private_key": "p",
			"xray.public_key":  "q",
			"xray.short_ids":   []any{"deadbeef", "01020304"},
			"xray.listen_port": float64(10443),
			"xray.mode":        "xhttp",
			"xray.xhttp_path":  "/abc",
			"xray.dest":        "127.0.0.1:8444",
		},
	}
	cfg, err := configFromOptions(opts)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if cfg.ListenPort != 10443 {
		t.Errorf("ListenPort: %d", cfg.ListenPort)
	}
	if cfg.Mode != ModeXHTTP {
		t.Errorf("Mode: %q", cfg.Mode)
	}
	if cfg.XHTTPPath != "/abc" {
		t.Errorf("XHTTPPath: %q", cfg.XHTTPPath)
	}
	if !reflect.DeepEqual(cfg.ShortIDs, []string{"deadbeef", "01020304"}) {
		t.Errorf("ShortIDs: %v", cfg.ShortIDs)
	}
	if cfg.Dest != "127.0.0.1:8444" {
		t.Errorf("Dest: %q", cfg.Dest)
	}
}

func TestConfigFromOptionsRejectsMissing(t *testing.T) {
	cases := []struct {
		name string
		opts transport.Options
	}{
		{"no domain", transport.Options{}},
		{"no uuid", transport.Options{Domain: "x.com", Extra: map[string]any{
			"xray.private_key": "p", "xray.public_key": "q",
			"xray.short_ids": []string{"deadbeef"},
		}}},
		{"empty extra", transport.Options{Domain: "x.com", Extra: map[string]any{}}},
		{"short_ids wrong type", transport.Options{Domain: "x.com", Extra: map[string]any{
			"xray.uuid":        "deadbeef-1234-4567-89ab-0123456789ab",
			"xray.private_key": "p", "xray.public_key": "q",
			"xray.short_ids": "not a slice",
		}}},
		{"listen_port not number", transport.Options{Domain: "x.com", Extra: map[string]any{
			"xray.uuid":        "deadbeef-1234-4567-89ab-0123456789ab",
			"xray.private_key": "p", "xray.public_key": "q",
			"xray.short_ids":   []string{"deadbeef"},
			"xray.listen_port": "443",
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := configFromOptions(tc.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestProbeUnreachable(t *testing.T) {
	// A pure unit test: dial 127.0.0.1:443 on the test host.
	// We don't assert OK, only that Probe returns without error and
	// reports a latency reading.
	tr, err := transport.Get(Name)
	if err != nil {
		t.Fatal(err)
	}
	res, err := tr.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Notes == "" {
		t.Fatal("Probe.Notes empty")
	}
}

func TestProbeReadsConfiguredPort(t *testing.T) {
	// Bring up a local listener on an arbitrary port, write a config
	// file pointing at that port, point a transportImpl at it, and
	// assert Probe both reports OK and includes the chosen port in
	// its Notes — proving Probe is no longer hardcoded to 443.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := validConfig(t)
	cfg.ListenPort = port
	rendered, err := Render(cfg)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfgPath := dir + "/config.json"
	if err := os.WriteFile(cfgPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	impl := &transportImpl{mgr: &Manager{Paths: Paths{Config: cfgPath}}}

	res, err := impl.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.OK {
		t.Fatalf("Probe should have connected: %+v", res)
	}
	wantSubstr := strconv.Itoa(port)
	if !strings.Contains(res.Notes, wantSubstr) {
		t.Fatalf("Probe didn't dial configured port %d: notes=%q", port, res.Notes)
	}
}

func TestProbeFallsBackWhenConfigMissing(t *testing.T) {
	impl := &transportImpl{mgr: &Manager{Paths: Paths{Config: "/nonexistent/xray-config.json"}}}
	res, err := impl.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// Whether 127.0.0.1:443 is reachable on the test host is
	// irrelevant — what we assert is that the fallback path was
	// taken and surfaced in Notes.
	if !strings.Contains(res.Notes, "config unreadable") {
		t.Fatalf("expected fallback in Notes, got: %q", res.Notes)
	}
}
