package amneziawg

import (
	"strings"
	"testing"

	"github.com/vmhlov/xray-aio/internal/transport"
)

func validExtra() map[string]any {
	o := goldObfuscation()
	return map[string]any{
		"amneziawg.private_key":     "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		"amneziawg.peer_public_key": "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		"amneziawg.jc":              o.Jc,
		"amneziawg.jmin":            o.Jmin,
		"amneziawg.jmax":            o.Jmax,
		"amneziawg.s1":              o.S1,
		"amneziawg.s2":              o.S2,
		"amneziawg.h1":              o.H1,
		"amneziawg.h2":              o.H2,
		"amneziawg.h3":              o.H3,
		"amneziawg.h4":              o.H4,
	}
}

func TestRegistered(t *testing.T) {
	tr, err := transport.Get(Name)
	if err != nil {
		t.Fatalf("Get(%q): %v", Name, err)
	}
	if tr.Name() != Name {
		t.Fatalf("got name %q, want %q", tr.Name(), Name)
	}
}

func TestConfigFromOptionsHappyPath(t *testing.T) {
	cfg, err := configFromOptions(transport.Options{
		Domain: "vmh-aio.site",
		Extra:  validExtra(),
	})
	if err != nil {
		t.Fatalf("configFromOptions: %v", err)
	}
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		t.Fatalf("missing keys: %+v", cfg)
	}
	if cfg.Endpoint != "vmh-aio.site:51842" {
		t.Errorf("Endpoint = %q, want vmh-aio.site:51842 (DefaultListenPort)", cfg.Endpoint)
	}
	if cfg.Obfuscation.Jc != 5 {
		t.Errorf("Jc = %d, want 5", cfg.Obfuscation.Jc)
	}
}

func TestConfigFromOptionsListenPortInEndpoint(t *testing.T) {
	extra := validExtra()
	extra["amneziawg.listen_port"] = 51999
	cfg, err := configFromOptions(transport.Options{
		Domain: "vmh-aio.site",
		Extra:  extra,
	})
	if err != nil {
		t.Fatalf("configFromOptions: %v", err)
	}
	if cfg.Endpoint != "vmh-aio.site:51999" {
		t.Errorf("Endpoint = %q, want vmh-aio.site:51999", cfg.Endpoint)
	}
	if cfg.ListenPort != 51999 {
		t.Errorf("ListenPort = %d, want 51999", cfg.ListenPort)
	}
}

func TestConfigFromOptionsNoDomainEndpointEmpty(t *testing.T) {
	cfg, err := configFromOptions(transport.Options{Extra: validExtra()})
	if err != nil {
		t.Fatalf("configFromOptions: %v", err)
	}
	if cfg.Endpoint != "" {
		t.Errorf("Endpoint = %q without Domain, want empty", cfg.Endpoint)
	}
}

func TestConfigFromOptionsRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		drop string
	}{
		{"private-key", "amneziawg.private_key"},
		{"peer-pub", "amneziawg.peer_public_key"},
		{"jc", "amneziawg.jc"},
		{"s1", "amneziawg.s1"},
		{"h1", "amneziawg.h1"},
		{"h4", "amneziawg.h4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			extra := validExtra()
			delete(extra, tc.drop)
			_, err := configFromOptions(transport.Options{Domain: "vmh-aio.site", Extra: extra})
			if err == nil {
				t.Fatalf("expected error when %s is missing", tc.drop)
			}
			if !strings.Contains(err.Error(), tc.drop) {
				t.Errorf("error %q does not name missing key %q", err.Error(), tc.drop)
			}
		})
	}
}

func TestConfigFromOptionsNumericCoercion(t *testing.T) {
	// Real-world callers (orchestrator) pass numeric values as int;
	// when the same map is round-tripped through encoding/json the
	// numbers come back as float64 (jc/jmin/...) and uint32-shaped
	// fields can also arrive as float64. Both must work.
	extra := validExtra()
	extra["amneziawg.jc"] = float64(5)
	extra["amneziawg.h1"] = float64(0xAAAAAAAA)
	cfg, err := configFromOptions(transport.Options{Extra: extra})
	if err != nil {
		t.Fatalf("configFromOptions: %v", err)
	}
	if cfg.Obfuscation.Jc != 5 {
		t.Errorf("Jc = %d, want 5", cfg.Obfuscation.Jc)
	}
	if cfg.Obfuscation.H1 != 0xAAAAAAAA {
		t.Errorf("H1 = %d, want %d", cfg.Obfuscation.H1, uint32(0xAAAAAAAA))
	}
}

func TestRequiredUint32StringForm(t *testing.T) {
	// Strings >= 2^31 must parse — strconv.Atoi would fail on 32-bit
	// hosts, so we use ParseUint(_, _, 32).
	got, err := requiredUint32(map[string]any{"k": "3000000000"}, "k")
	if err != nil {
		t.Fatalf("requiredUint32: %v", err)
	}
	if got != 3000000000 {
		t.Errorf("got %d, want 3000000000", got)
	}
}

func TestRequiredUint32Rejects(t *testing.T) {
	cases := []struct {
		name string
		val  any
	}{
		{"negative-int", -1},
		{"too-large-int64", int64(int64(^uint32(0)) + 1)},
		{"negative-float", float64(-1)},
		{"too-large-float", float64(^uint32(0)) + 100},
		{"non-numeric-string", "abc"},
		{"unsupported-type", []byte("x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requiredUint32(map[string]any{"k": tc.val}, "k")
			if err == nil {
				t.Errorf("expected error for %v", tc.val)
			}
		})
	}
}

func TestNewReturnsLiveTransport(t *testing.T) {
	tr := New()
	if tr == nil {
		t.Fatal("New returned nil")
	}
	if tr.Name() != Name {
		t.Errorf("Name = %q, want %q", tr.Name(), Name)
	}
}
