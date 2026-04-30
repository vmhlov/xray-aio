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
		// Site address now lists the named host first (drives
		// LE issuance) and the bare port second (lifts the host
		// matcher off forward_proxy so HTTP/1.1 CONNECT works).
		"example.com:443, :443 {",
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
	if !strings.Contains(out, "example.com:443, :443 {") {
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
	if !strings.Contains(out, "example.com:9443, :9443 {") {
		t.Fatalf("expected example.com:9443 site block:\n%s", out)
	}
	if strings.Contains(out, "example.com:443, :443 {") {
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

// TestRenderWrapsForwardProxyInRouteBlock pins the regression that
// took down PR #10's first VPS deployment: Caddy's Caddyfile adapter
// reorders top-level directives by a hard-coded schema in which
// file_server runs before any third-party handler, so a naïve
// `forward_proxy ; file_server` template compiled to a route where
// file_server responded to CONNECT first and forward_proxy never
// ran. Wrapping the trio in `route { }` blocks the reorder; this
// test fails fast if a future edit removes the route.
func TestRenderWrapsForwardProxyInRouteBlock(t *testing.T) {
	out, err := Render(goodOpts())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// The proxy site block must contain a route that holds
	// forward_proxy, root, and file_server in that order.
	siteOpen := strings.Index(out, "example.com:443, :443 {")
	if siteOpen < 0 {
		t.Fatalf("proxy site block missing:\n%s", out)
	}
	siteEnd := strings.Index(out[siteOpen:], "\n}\n")
	if siteEnd < 0 {
		t.Fatalf("proxy site block not terminated:\n%s", out)
	}
	site := out[siteOpen : siteOpen+siteEnd]
	routeOpen := strings.Index(site, "route {")
	if routeOpen < 0 {
		t.Fatalf("forward_proxy must be wrapped in route { }:\n%s", site)
	}
	// Within the route block, forward_proxy must precede file_server
	// (textual order is what Caddy preserves inside a route).
	rb := site[routeOpen:]
	fp := strings.Index(rb, "forward_proxy")
	fs := strings.Index(rb, "file_server")
	if fp < 0 || fs < 0 {
		t.Fatalf("forward_proxy or file_server missing inside route block:\n%s", rb)
	}
	if fp > fs {
		t.Fatalf("forward_proxy must appear BEFORE file_server inside route { }:\n%s", rb)
	}
	// The selfsteal site must NOT have a route block — it is a
	// pure static server, no proxy semantics.
	selfOpen := strings.Index(out, "example.com:8443 {")
	if selfOpen < 0 {
		t.Fatalf("selfsteal site block missing:\n%s", out)
	}
	selfEnd := strings.Index(out[selfOpen:], "\n}\n")
	if selfEnd < 0 {
		t.Fatalf("selfsteal site block not terminated:\n%s", out)
	}
	if strings.Contains(out[selfOpen:selfOpen+selfEnd], "route {") {
		t.Fatalf("selfsteal block must not wrap in route — pure file_server:\n%s",
			out[selfOpen:selfOpen+selfEnd])
	}
}

// TestRenderListsBarePortAddrForForwardProxy pins the regression
// that surfaced after PR #11's directive-order fix: the Caddyfile
// adapter compiles a single named address `example.com:443` into a
// route guarded by `host=example.com`, but HTTP/1.1 CONNECT carries
// `Host: <target>:port` which never matches the proxy's own
// hostname — forward_proxy is unreachable for HTTP/1.1 clients.
// The named-and-bare pair `example.com:443, :443` lifts the host
// matcher off the route while keeping LE issuance for example.com.
// HTTP/2 naïve clients use `:authority` = proxy hostname so they
// would match either form, but operators pointing curl / pacparser
// / generic HTTP/1.1 clients at the proxy must work too.
func TestRenderListsBarePortAddrForForwardProxy(t *testing.T) {
	out, err := Render(goodOpts())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "example.com:443, :443 {") {
		t.Fatalf("expected named+bare site address `example.com:443, :443 {`:\n%s", out)
	}
	// The selfsteal site MUST keep its named address only — no
	// bare-port escape hatch — because it is REALITY's loopback
	// upstream and is supposed to host-gate everything that
	// reaches it.
	if !strings.Contains(out, "example.com:8443 {") {
		t.Fatalf("selfsteal site must use named-only address:\n%s", out)
	}
	if strings.Contains(out, ":8443, :8443") || strings.Contains(out, "example.com:8443, :8443") {
		t.Fatalf("selfsteal site must NOT add a bare-port sibling — it's host-gated:\n%s", out)
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
