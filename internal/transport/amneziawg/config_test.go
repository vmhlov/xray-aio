package amneziawg

import (
	"strings"
	"testing"
)

func goldObfuscation() Obfuscation {
	return Obfuscation{
		Jc:   5,
		Jmin: 50,
		Jmax: 1000,
		S1:   80,
		S2:   60,
		H1:   0xAAAAAAAA,
		H2:   0xBBBBBBBB,
		H3:   0xCCCCCCCC,
		H4:   0xDDDDDDDD,
	}
}

func TestRenderServerGolden(t *testing.T) {
	cfg := Config{
		PrivateKey:    "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey: "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		Obfuscation:   goldObfuscation(),
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "# Managed by xray-aio. Do not edit by hand — re-run `xray-aio install`.\n" +
		"# Server address is applied by the systemd unit's `ip addr add` hook,\n" +
		"# not by `awg setconf`, which rejects wg-quick directives.\n" +
		"[Interface]\n" +
		"PrivateKey = MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=\n" +
		"ListenPort = 51842\n" +
		"Jc = 5\n" +
		"Jmin = 50\n" +
		"Jmax = 1000\n" +
		"S1 = 80\n" +
		"S2 = 60\n" +
		"H1 = 2863311530\n" +
		"H2 = 3149642683\n" +
		"H3 = 3435973836\n" +
		"H4 = 3722304989\n" +
		"\n[Peer]\n" +
		"PublicKey = rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=\n" +
		"AllowedIPs = 10.66.66.2/32\n"
	if got != want {
		t.Fatalf("render mismatch.\nGOT:\n%s\nWANT:\n%s", got, want)
	}
}

func TestRenderServerWithPresharedKey(t *testing.T) {
	cfg := Config{
		PrivateKey:       "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey:    "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		PeerPresharedKey: "PSKpsk5jU3aS1L9rBkPm2nQyXfA1HkMEgVZ7zCJ7E0w=",
		Obfuscation:      goldObfuscation(),
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(got, "PresharedKey = PSKpsk5jU3aS1L9rBkPm2nQyXfA1HkMEgVZ7zCJ7E0w=") {
		t.Fatalf("expected PresharedKey line, got:\n%s", got)
	}
}

func TestRenderServerOverrides(t *testing.T) {
	cfg := Config{
		PrivateKey:    "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey: "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		ServerAddress: "10.99.0.1/24",
		PeerAddress:   "10.99.0.2/32",
		ListenPort:    51999,
		Obfuscation:   goldObfuscation(),
	}
	got, err := Render(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// Server-side render is fed to `awg setconf`, which rejects
	// the wg-quick `Address` directive. The CIDR override flows
	// to the systemd unit's `ip addr add` hook (covered by
	// manager_test.go::TestManagerInstallUnit) and to AllowedIPs
	// only via PeerAddress.
	for _, want := range []string{
		"ListenPort = 51999",
		"AllowedIPs = 10.99.0.2/32",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected %q in output, got:\n%s", want, got)
		}
	}
	for _, banned := range []string{
		"Address =",
		"DNS =",
		"MTU =",
	} {
		if strings.Contains(got, banned) {
			t.Fatalf("server render must omit wg-quick directive %q (rejected by `awg setconf`); got:\n%s", banned, got)
		}
	}
}

func TestRenderPeerGolden(t *testing.T) {
	cfg := Config{
		PrivateKey:    "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey: "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		Endpoint:      "vmh-aio.site:51842",
		Obfuscation:   goldObfuscation(),
	}
	peerPriv := "9oV5jU3aS1L9rBkPm2nQyXfA1HkMEgVZ7zCJ7E0xWQ8="
	serverPub := "ServerPubAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0="
	got, err := RenderPeer(cfg, peerPriv, serverPub)
	if err != nil {
		t.Fatalf("render peer: %v", err)
	}
	want := "# Managed by xray-aio. Import into AmneziaWG client (NOT vanilla WireGuard).\n" +
		"[Interface]\n" +
		"PrivateKey = 9oV5jU3aS1L9rBkPm2nQyXfA1HkMEgVZ7zCJ7E0xWQ8=\n" +
		"Address = 10.66.66.2/32\n" +
		"DNS = 1.1.1.1\n" +
		"MTU = 1380\n" +
		"Jc = 5\n" +
		"Jmin = 50\n" +
		"Jmax = 1000\n" +
		"S1 = 80\n" +
		"S2 = 60\n" +
		"H1 = 2863311530\n" +
		"H2 = 3149642683\n" +
		"H3 = 3435973836\n" +
		"H4 = 3722304989\n" +
		"\n[Peer]\n" +
		"PublicKey = ServerPubAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0=\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\n" +
		"Endpoint = vmh-aio.site:51842\n" +
		"PersistentKeepalive = 25\n"
	if got != want {
		t.Fatalf("peer render mismatch.\nGOT:\n%s\nWANT:\n%s", got, want)
	}
}

func TestRenderPeerErrors(t *testing.T) {
	cfg := Config{
		PrivateKey:    "MEgVZ7zCJ7E0xWQp8oV5jU3aS1L9rBkPm2nQyXfA1Hk=",
		PeerPublicKey: "rJ8KtT4lO2dV9bF5mNcQ1pWyEXuY3sZA6vH8Lk0i7+I=",
		Endpoint:      "vmh-aio.site:51842",
		Obfuscation:   goldObfuscation(),
	}
	cases := []struct {
		name string
		mut  func(*Config) (peerPriv, serverPub string)
		want string
	}{
		{"empty-peer-priv", func(c *Config) (string, string) { return "", "ServerPub" }, "peerPrivateKey"},
		{"empty-server-pub", func(c *Config) (string, string) { return "PeerPriv", "" }, "serverPublicKey"},
		{"empty-endpoint", func(c *Config) (string, string) { c.Endpoint = ""; return "PeerPriv", "ServerPub" }, "Endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			peerPriv, serverPub := tc.mut(&c)
			_, err := RenderPeer(c, peerPriv, serverPub)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestConfigValidateRejects(t *testing.T) {
	base := Config{
		PrivateKey:    "x",
		PeerPublicKey: "y",
		Obfuscation:   goldObfuscation(),
	}
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"empty-priv", func(c *Config) { c.PrivateKey = "" }, "PrivateKey"},
		{"empty-peer-pub", func(c *Config) { c.PeerPublicKey = "" }, "PeerPublicKey"},
		{"port-negative", func(c *Config) { c.ListenPort = -1 }, "ListenPort"},
		{"port-over", func(c *Config) { c.ListenPort = 70000 }, "ListenPort"},
		{"mtu-negative", func(c *Config) { c.MTU = -1 }, "MTU"},
		{"mtu-over", func(c *Config) { c.MTU = 99999 }, "MTU"},
		{"bad-obfuscation", func(c *Config) { c.Obfuscation.Jc = 0 }, "Jc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}
