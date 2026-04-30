package hysteria2

import (
	"strings"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "empty domain",
			cfg:     Config{Password: "x"},
			wantErr: "Domain is required",
		},
		{
			name:    "empty password",
			cfg:     Config{Domain: "vpn.example.com"},
			wantErr: "Password is required",
		},
		{
			name:    "negative port",
			cfg:     Config{Domain: "vpn.example.com", Password: "x", ListenPort: -1},
			wantErr: "ListenPort -1 out of range",
		},
		{
			name:    "out-of-range port",
			cfg:     Config{Domain: "vpn.example.com", Password: "x", ListenPort: 70000},
			wantErr: "ListenPort 70000 out of range",
		},
		{
			name: "minimal valid",
			cfg:  Config{Domain: "vpn.example.com", Password: "x"},
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
		Domain:   "vpn.example.com",
		Password: "s3cret",
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := `# Managed by xray-aio. Do not edit by hand — re-run ` + "`xray-aio install`" + `.
listen: :443

tls:
  cert: /var/lib/caddy/caddy/certificates/acme-v02.api.letsencrypt.org-directory/vpn.example.com/vpn.example.com.crt
  key: /var/lib/caddy/caddy/certificates/acme-v02.api.letsencrypt.org-directory/vpn.example.com/vpn.example.com.key

auth:
  type: password
  password: s3cret

masquerade:
  type: proxy
  proxy:
    url: https://127.0.0.1:8443
    rewriteHost: true
`
	if got != want {
		t.Errorf("Render output diverged from golden.\n--- want ---\n%s\n--- got ---\n%s", want, got)
	}
}

func TestRenderHonoursOverrides(t *testing.T) {
	cfg := Config{
		Domain:        "vpn.example.com",
		Password:      "s3cret",
		ListenPort:    11443,
		MasqueradeURL: "https://upstream.example.com",
		CertPath:      "/etc/ssl/foo.pem",
		KeyPath:       "/etc/ssl/foo.key",
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, sub := range []string{
		"listen: :11443",
		"cert: /etc/ssl/foo.pem",
		"key: /etc/ssl/foo.key",
		"url: https://upstream.example.com",
		"password: s3cret",
	} {
		if !strings.Contains(got, sub) {
			t.Errorf("rendered config missing %q\n%s", sub, got)
		}
	}
}

func TestCertPathsDefaultsTrackDomain(t *testing.T) {
	cfg := Config{Domain: "a.example.com"}
	cert, key := cfg.CertPaths()
	if !strings.HasSuffix(cert, "/a.example.com/a.example.com.crt") {
		t.Errorf("cert path %q does not end with /<domain>/<domain>.crt", cert)
	}
	if !strings.HasSuffix(key, "/a.example.com/a.example.com.key") {
		t.Errorf("key path %q does not end with /<domain>/<domain>.key", key)
	}
}
