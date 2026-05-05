package mtproto

import (
	"context"
	"strings"
	"testing"

	"github.com/vmhlov/xray-aio/internal/transport"
)

func TestTransportRegistered(t *testing.T) {
	tr, err := transport.Get(Name)
	if err != nil {
		t.Fatalf("transport.Get(%q): %v", Name, err)
	}
	if tr.Name() != Name {
		t.Errorf("Name=%q, want %q", tr.Name(), Name)
	}
}

func TestConfigFromOptions(t *testing.T) {
	cases := []struct {
		name    string
		opts    transport.Options
		want    Config
		wantErr string
	}{
		{
			name:    "missing domain",
			opts:    transport.Options{Extra: map[string]any{"mtproto.secret": "deadbeefcafebabedeadbeefcafebabe"}},
			wantErr: "Domain is required",
		},
		{
			name:    "missing secret",
			opts:    transport.Options{Domain: "vpn.example.com", Extra: map[string]any{}},
			wantErr: "mtproto.secret",
		},
		{
			name: "minimal",
			opts: transport.Options{Domain: "vpn.example.com", Extra: map[string]any{
				"mtproto.secret": "deadbeefcafebabedeadbeefcafebabe",
			}},
			want: Config{
				Domain:     "vpn.example.com",
				Secret:     "deadbeefcafebabedeadbeefcafebabe",
				ListenPort: DefaultListenPort,
			},
		},
		{
			name: "full override",
			opts: transport.Options{Domain: "vpn.example.com", Extra: map[string]any{
				"mtproto.secret":      "cafebabecafebabecafebabecafebabe",
				"mtproto.username":    "alice",
				"mtproto.listen_port": 9443,
				"mtproto.tls_domain":  "www.cloudflare.com",
			}},
			want: Config{
				Domain:     "vpn.example.com",
				Secret:     "cafebabecafebabecafebabecafebabe",
				Username:   "alice",
				ListenPort: 9443,
				TLSDomain:  "www.cloudflare.com",
			},
		},
		{
			name: "listen_port from float64 (JSON round-trip)",
			opts: transport.Options{Domain: "vpn.example.com", Extra: map[string]any{
				"mtproto.secret":      "deadbeefcafebabedeadbeefcafebabe",
				"mtproto.listen_port": float64(9443),
			}},
			want: Config{
				Domain:     "vpn.example.com",
				Secret:     "deadbeefcafebabedeadbeefcafebabe",
				ListenPort: 9443,
			},
		},
		{
			name: "listen_port from string",
			opts: transport.Options{Domain: "vpn.example.com", Extra: map[string]any{
				"mtproto.secret":      "deadbeefcafebabedeadbeefcafebabe",
				"mtproto.listen_port": "9443",
			}},
			want: Config{
				Domain:     "vpn.example.com",
				Secret:     "deadbeefcafebabedeadbeefcafebabe",
				ListenPort: 9443,
			},
		},
		{
			name: "listen_port non-numeric",
			opts: transport.Options{Domain: "vpn.example.com", Extra: map[string]any{
				"mtproto.secret":      "deadbeefcafebabedeadbeefcafebabe",
				"mtproto.listen_port": "not-a-port",
			}},
			wantErr: "not numeric",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := configFromOptions(tc.opts)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("want error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err=%q, want substring %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestTransportProbeNoListener(t *testing.T) {
	// No listener on 127.0.0.1:8883 in the test binary — Probe should
	// cleanly report OK=false with a connection-refused-ish note, not
	// panic or return an error.
	ti := &transportImpl{mgr: NewManager()}
	got, err := ti.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got.OK {
		t.Errorf("Probe.OK=true despite no listener; notes=%q", got.Notes)
	}
	if got.Notes == "" {
		t.Errorf("Probe.Notes empty on failure path")
	}
}
