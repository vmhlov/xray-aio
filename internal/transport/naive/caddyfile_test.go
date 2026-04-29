package naive

import (
	"strings"
	"testing"
)

func goodOpts() Options {
	return Options{
		Domain:          "example.com",
		Username:        "alice",
		Password:        "s3cret",
		ProbeResistance: "secret-host.example",
		Email:           "ops@example.com",
	}
}

func TestRenderHappy(t *testing.T) {
	out, err := Render(goodOpts())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"example.com:443 {",
		"basic_auth alice s3cret",
		"hide_ip",
		"hide_via",
		"probe_resistance secret-host.example",
		"root * " + DefaultSiteRoot,
		"admin " + DefaultAdminSocket,
		"email ops@example.com",
		"X-Content-Type-Options nosniff",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// When Email is set, Caddy auto-issues from the global config
	// block — no explicit `tls` directive should be emitted.
	if strings.Contains(out, "tls internal") {
		t.Errorf("'tls internal' must not appear when Email is set:\n%s", out)
	}
}

func TestRenderTLSInternalWhenNoEmail(t *testing.T) {
	o := goodOpts()
	o.Email = ""
	out, err := Render(o)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "tls internal") {
		t.Fatalf("expected 'tls internal' fallback:\n%s", out)
	}
	if strings.Contains(out, "email ") {
		t.Fatalf("email block must be omitted when Email is empty:\n%s", out)
	}
	// Domain still required in site address even without LE so
	// `tls internal` knows what subject to issue.
	if !strings.Contains(out, "example.com:443 {") {
		t.Fatalf("Domain must remain in site address:\n%s", out)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	mut := func(f func(*Options)) Options {
		o := goodOpts()
		f(&o)
		return o
	}
	cases := []struct {
		name string
		o    Options
	}{
		{"empty domain", mut(func(o *Options) { o.Domain = "" })},
		{"domain whitespace", mut(func(o *Options) { o.Domain = "ex ample.com" })},
		{"domain brace", mut(func(o *Options) { o.Domain = "ex.com}\n;import" })},
		{"username empty", mut(func(o *Options) { o.Username = "" })},
		{"password empty", mut(func(o *Options) { o.Password = "" })},
		{"username has space", mut(func(o *Options) { o.Username = "a b" })},
		{"password has newline", mut(func(o *Options) { o.Password = "p\nass" })},
		{"username has colon", mut(func(o *Options) { o.Username = "al:ice" })},
		{"password has colon", mut(func(o *Options) { o.Password = "x:y" })},
		{"username has quote", mut(func(o *Options) { o.Username = `a"b` })},
		{"probe resistance empty", mut(func(o *Options) { o.ProbeResistance = "" })},
		{"probe resistance whitespace", mut(func(o *Options) { o.ProbeResistance = "secret host" })},
		{"site root relative", mut(func(o *Options) { o.SiteRoot = "selfsteal" })},
		{"site root injection", mut(func(o *Options) { o.SiteRoot = "/var/lib/{evil}" })},
		{"port too high", mut(func(o *Options) { o.ListenPort = 70000 })},
		{"port negative", mut(func(o *Options) { o.ListenPort = -1 })},
		{"email injection", mut(func(o *Options) { o.Email = "x\"@e.com" })},
		{"admin injection", mut(func(o *Options) { o.AdminSocket = "127.0.0.1:2019\nimport" })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render(tc.o); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRenderAdminOff(t *testing.T) {
	o := goodOpts()
	o.AdminSocket = "off"
	out, err := Render(o)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "admin off") {
		t.Fatalf("expected 'admin off' verbatim:\n%s", out)
	}
}

func TestRenderCustomPort(t *testing.T) {
	o := goodOpts()
	o.ListenPort = 9443
	out, err := Render(o)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "example.com:9443 {") {
		t.Fatalf("expected example.com:9443 site block:\n%s", out)
	}
	if strings.Contains(out, "example.com:443 {") {
		t.Fatalf("default port leaked:\n%s", out)
	}
}

func TestRenderEmitsSelfStealSite(t *testing.T) {
	o := goodOpts()
	out, err := Render(o)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "example.com:8443 {") {
		t.Fatalf("expected default selfsteal site on :8443 in output:\n%s", out)
	}
	if !strings.Contains(out, "root * "+DefaultSelfStealRoot) {
		t.Fatalf("expected selfsteal root directive:\n%s", out)
	}
	// The selfsteal block must NOT contain forward_proxy.
	idx := strings.Index(out, "example.com:8443 {")
	if idx < 0 {
		t.Fatalf("selfsteal block missing")
	}
	end := strings.Index(out[idx:], "\n}\n")
	if end < 0 {
		t.Fatalf("selfsteal block not terminated:\n%s", out)
	}
	block := out[idx : idx+end]
	if strings.Contains(block, "forward_proxy") {
		t.Fatalf("selfsteal block must not include forward_proxy:\n%s", block)
	}
}

func TestRenderRejectsSelfStealCollision(t *testing.T) {
	t.Run("port collision", func(t *testing.T) {
		o := goodOpts()
		o.ListenPort = 8443
		o.SelfStealPort = 8443
		if _, err := Render(o); err == nil {
			t.Fatal("expected error when SelfStealPort == ListenPort")
		}
	})
	t.Run("root collision", func(t *testing.T) {
		o := goodOpts()
		o.SiteRoot = "/var/lib/shared"
		o.SelfStealRoot = "/var/lib/shared"
		if _, err := Render(o); err == nil {
			t.Fatal("expected error when SelfStealRoot == SiteRoot")
		}
	})
}
