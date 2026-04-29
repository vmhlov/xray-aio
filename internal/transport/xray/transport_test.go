package xray

import (
	"context"
	"reflect"
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
