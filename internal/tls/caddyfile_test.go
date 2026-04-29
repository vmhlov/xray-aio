package tls

import (
	"strings"
	"testing"
)

func TestRenderMinimal(t *testing.T) {
	out, err := Render(Options{Domain: "example.com"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, out, "example.com")
	mustContain(t, out, "admin off")
	mustContain(t, out, "auto_https disable_redirects")
	mustContain(t, out, "redir https://example.com{uri} permanent")
	mustContain(t, out, "root * "+DefaultSelfStealRoot)
	mustContain(t, out, "X-Content-Type-Options nosniff")
	if strings.Contains(out, "email ") {
		t.Fatal("email block must be omitted when Email is empty")
	}
}

func TestRenderWithEmailAndAdmin(t *testing.T) {
	out, err := Render(Options{
		Domain:        "example.com",
		Email:         "ops@example.com",
		SelfStealRoot: "/srv/site",
		AdminListen:   "127.0.0.1:2019",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContain(t, out, "email ops@example.com")
	mustContain(t, out, "root * /srv/site")
	mustContain(t, out, "admin 127.0.0.1:2019")
	if strings.Contains(out, "admin off") {
		t.Fatal("admin off must not appear when AdminListen is set")
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"empty domain", Options{}},
		{"domain whitespace", Options{Domain: "ex ample.com"}},
		{"domain brace injection", Options{Domain: "example.com}\nimport /etc/passwd\n{"}},
		{"email whitespace", Options{Domain: "example.com", Email: "ops @example.com"}},
		{"selfsteal relative", Options{Domain: "example.com", SelfStealRoot: "relative/path"}},
		{"admin injection", Options{Domain: "example.com", AdminListen: "127.0.0.1:2019\nimport"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render(tc.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSelfStealEmbedded(t *testing.T) {
	if len(SelfStealIndex) == 0 {
		t.Fatal("SelfStealIndex is empty (embed missing?)")
	}
	preview := SelfStealIndex
	if len(preview) > 80 {
		preview = preview[:80]
	}
	if !strings.Contains(string(SelfStealIndex), "<!doctype html>") {
		t.Fatalf("doesn't look like HTML: %q", preview)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("output missing %q\n--- output ---\n%s", needle, haystack)
	}
}
