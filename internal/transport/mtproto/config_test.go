package mtproto

import (
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	validSecret := "deadbeefcafebabedeadbeefcafebabe"
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "empty domain",
			cfg:     Config{Secret: validSecret},
			wantErr: "Domain is required",
		},
		{
			name:    "empty secret",
			cfg:     Config{Domain: "vpn.example.com"},
			wantErr: "Secret is required",
		},
		{
			name:    "short secret",
			cfg:     Config{Domain: "vpn.example.com", Secret: "deadbeef"},
			wantErr: "Secret must be 32 hex chars",
		},
		{
			name:    "non-hex secret",
			cfg:     Config{Domain: "vpn.example.com", Secret: "nothexnothexnothexnothexnothexzz"},
			wantErr: "Secret is not valid hex",
		},
		{
			name:    "negative port",
			cfg:     Config{Domain: "vpn.example.com", Secret: validSecret, ListenPort: -1},
			wantErr: "ListenPort -1 out of range",
		},
		{
			name:    "out-of-range port",
			cfg:     Config{Domain: "vpn.example.com", Secret: validSecret, ListenPort: 70000},
			wantErr: "ListenPort 70000 out of range",
		},
		{
			name:    "username with space",
			cfg:     Config{Domain: "vpn.example.com", Secret: validSecret, Username: "evil user"},
			wantErr: "Username",
		},
		{
			name:    "tls_domain with quote",
			cfg:     Config{Domain: "vpn.example.com", Secret: validSecret, TLSDomain: `foo".com`},
			wantErr: "TLSDomain",
		},
		{
			name: "minimal valid",
			cfg:  Config{Domain: "vpn.example.com", Secret: validSecret},
		},
		{
			name: "all fields valid",
			cfg: Config{
				Domain:     "vpn.example.com",
				Secret:     validSecret,
				Username:   "alice",
				TLSDomain:  "www.cloudflare.com",
				ListenPort: 8443,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRenderDefaults(t *testing.T) {
	cfg := Config{
		Domain: "vpn.example.com",
		Secret: "deadbeefcafebabedeadbeefcafebabe",
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Required invariants — match golden only in TestRenderGolden.
	wants := []string{
		"[general]",
		"use_middle_proxy = true",
		"[general.modes]",
		"classic = false",
		"secure = false",
		"tls = true",
		"[server]",
		"port = 8883",
		"[[server.listeners]]",
		`ip = "0.0.0.0"`,
		"[censorship]",
		`tls_domain = "www.microsoft.com"`,
		"mask = true",
		"tls_emulation = true",
		"[access.users]",
		`xray-aio = "deadbeefcafebabedeadbeefcafebabe"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("Render output missing %q; got:\n%s", w, got)
		}
	}
}

func TestRenderOverrides(t *testing.T) {
	cfg := Config{
		Domain:     "vpn.example.com",
		Secret:     "CAFEBABECAFEBABECAFEBABECAFEBABE",
		Username:   "alice",
		TLSDomain:  "www.cloudflare.com",
		ListenPort: 9443,
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Secret must be lower-cased in the TOML regardless of input
	// case, so the golden test stays stable even when operators feed
	// upper-case hex from a different generator.
	wants := []string{
		"port = 9443",
		`tls_domain = "www.cloudflare.com"`,
		`alice = "cafebabecafebabecafebabecafebabe"`,
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("Render missing %q; got:\n%s", w, got)
		}
	}
	if strings.Contains(got, "CAFEBABE") {
		t.Errorf("Render leaked upper-case secret into TOML; got:\n%s", got)
	}
}

func TestRenderValidateFailsRendering(t *testing.T) {
	_, err := Render(Config{Domain: "", Secret: "bad"})
	if err == nil {
		t.Fatalf("Render of invalid cfg should fail")
	}
}
