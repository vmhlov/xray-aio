package naive

import (
	"context"
	"net"
	"os"
	"path/filepath"
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

func TestOptionsFromMinimal(t *testing.T) {
	in := transport.Options{
		Domain: "example.com",
		Extra: map[string]any{
			"naive.username": "alice",
			"naive.password": "secret",
		},
	}
	o, err := optionsFrom(in)
	if err != nil {
		t.Fatalf("optionsFrom: %v", err)
	}
	if o.Domain != "example.com" || o.Username != "alice" || o.Password != "secret" {
		t.Fatalf("unexpected: %+v", o)
	}
	if o.ListenPort != DefaultListenPort {
		t.Errorf("ListenPort default: %d", o.ListenPort)
	}
	if !strings.HasSuffix(o.ProbeResistance, ".invalid") {
		t.Errorf("ProbeResistance must default to *.invalid: %q", o.ProbeResistance)
	}
}

func TestOptionsFromAcceptsJSONShape(t *testing.T) {
	in := transport.Options{
		Domain: "example.com",
		Extra: map[string]any{
			"naive.username":         "alice",
			"naive.password":         "secret",
			"naive.listen_port":      float64(10443),
			"naive.probe_resistance": "preset.invalid",
			"naive.site_root":        "/srv/x",
			"naive.admin_socket":     "off",
			"naive.build_url":        "https://mirror.example/caddy",
		},
	}
	o, err := optionsFrom(in)
	if err != nil {
		t.Fatalf("optionsFrom: %v", err)
	}
	if o.ListenPort != 10443 {
		t.Errorf("ListenPort: %d", o.ListenPort)
	}
	if o.ProbeResistance != "preset.invalid" {
		t.Errorf("ProbeResistance: %q", o.ProbeResistance)
	}
	if o.SiteRoot != "/srv/x" {
		t.Errorf("SiteRoot: %q", o.SiteRoot)
	}
	if o.AdminSocket != "off" {
		t.Errorf("AdminSocket: %q", o.AdminSocket)
	}
}

func TestOptionsFromRejectsMissing(t *testing.T) {
	cases := []struct {
		name string
		in   transport.Options
	}{
		{"no domain", transport.Options{}},
		{"no username", transport.Options{Domain: "x.com", Extra: map[string]any{
			"naive.password": "p",
		}}},
		{"no password", transport.Options{Domain: "x.com", Extra: map[string]any{
			"naive.username": "u",
		}}},
		{"port not number", transport.Options{Domain: "x.com", Extra: map[string]any{
			"naive.username":    "u",
			"naive.password":    "p",
			"naive.listen_port": "443",
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := optionsFrom(tc.in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParsePortFromCaddyfile(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
		err  bool
	}{
		{"default", "{\n\tadmin off\n}\n\n:443 {\n\tforward_proxy {\n\t}\n}\n", 443, false},
		{"non-default", ":10443 {\n}\n", 10443, false},
		{"with whitespace before brace", ":8443  {\n}\n", 8443, false},
		{"no site block", "{\n\tadmin off\n}\n", 0, true},
		{"non-numeric", ":abcd {\n}\n", 0, true},
		{"out of range", ":99999 {\n}\n", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePortFromCaddyfile([]byte(tc.body))
			if tc.err {
				if err == nil {
					t.Fatalf("expected error, got %d", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestProbeReadsConfiguredPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	o := goodOpts()
	o.ListenPort = port
	rendered, err := Render(o)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cfgPath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	impl := &transportImpl{mgr: &Manager{Paths: Paths{Caddyfile: cfgPath}}}
	res, err := impl.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.OK {
		t.Fatalf("Probe should connect: %+v", res)
	}
	if !strings.Contains(res.Notes, strconv.Itoa(port)) {
		t.Fatalf("Probe didn't dial configured port %d: notes=%q", port, res.Notes)
	}
}

func TestProbeFallsBackWhenConfigMissing(t *testing.T) {
	impl := &transportImpl{mgr: &Manager{Paths: Paths{Caddyfile: "/nonexistent/Caddyfile"}}}
	res, err := impl.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !strings.Contains(res.Notes, "config unreadable") {
		t.Fatalf("expected fallback notice, got: %q", res.Notes)
	}
}
