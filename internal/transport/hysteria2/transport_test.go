package hysteria2

import (
	"context"
	"strings"
	"testing"

	"github.com/vmhlov/xray-aio/internal/transport"
)

func TestNewProducesNamedTransport(t *testing.T) {
	tt := New()
	if tt.Name() != "hysteria2" {
		t.Errorf("Name = %q, want hysteria2", tt.Name())
	}
}

func TestRegistryHasHysteria2(t *testing.T) {
	tt, err := transport.Get("hysteria2")
	if err != nil {
		t.Fatalf("transport.Get: %v", err)
	}
	if tt.Name() != "hysteria2" {
		t.Errorf("Name = %q, want hysteria2", tt.Name())
	}
}

func TestConfigFromOptionsRequiresPassword(t *testing.T) {
	_, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra:  map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for missing password")
	}
	if !strings.Contains(err.Error(), "hysteria2.password") {
		t.Errorf("error %q does not mention hysteria2.password", err)
	}
}

func TestConfigFromOptionsRequiresDomain(t *testing.T) {
	_, err := configFromOptions(transport.Options{
		Extra: map[string]any{"hysteria2.password": "x"},
	})
	if err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestConfigFromOptionsHonoursOverrides(t *testing.T) {
	cfg, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra: map[string]any{
			"hysteria2.password":       "p",
			"hysteria2.listen_port":    11443,
			"hysteria2.masquerade_url": "https://decoy.example.com",
			"hysteria2.cert_path":      "/etc/ssl/c.pem",
			"hysteria2.key_path":       "/etc/ssl/k.pem",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenPort != 11443 {
		t.Errorf("ListenPort = %d, want 11443", cfg.ListenPort)
	}
	if cfg.MasqueradeURL != "https://decoy.example.com" {
		t.Errorf("MasqueradeURL = %q", cfg.MasqueradeURL)
	}
	if cfg.CertPath != "/etc/ssl/c.pem" || cfg.KeyPath != "/etc/ssl/k.pem" {
		t.Errorf("cert/key override not honoured: %+v", cfg)
	}
}

func TestConfigFromOptionsMasqueradeInsecure(t *testing.T) {
	cfg, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra: map[string]any{
			"hysteria2.password":            "p",
			"hysteria2.masquerade_insecure": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MasqueradeInsecure {
		t.Errorf("MasqueradeInsecure = false, want true")
	}
	cfg2, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra:  map[string]any{"hysteria2.password": "p"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.MasqueradeInsecure {
		t.Errorf("MasqueradeInsecure = true by default; want false (operator-pinned masquerade keeps verification)")
	}
}

func TestConfigFromOptionsAcceptsNumericStrings(t *testing.T) {
	cfg, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra: map[string]any{
			"hysteria2.password":    "p",
			"hysteria2.listen_port": "11443",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenPort != 11443 {
		t.Errorf("ListenPort = %d, want 11443", cfg.ListenPort)
	}
}

func TestConfigFromOptionsRejectsBadPort(t *testing.T) {
	_, err := configFromOptions(transport.Options{
		Domain: "vpn.example.com",
		Extra: map[string]any{
			"hysteria2.password":    "p",
			"hysteria2.listen_port": "not-a-number",
		},
	})
	if err == nil {
		t.Fatal("expected error for non-numeric port")
	}
}

func TestProbeOnUnusedPortDoesNotPanic(t *testing.T) {
	// A UDP "connect" on a free port still binds without an error
	// because UDP is connectionless. So this just verifies the call
	// path is wired up and returns a populated ProbeResult.
	tt := New()
	res, err := tt.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Notes == "" {
		t.Errorf("expected non-empty Notes, got %+v", res)
	}
}
