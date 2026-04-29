package subscribe

import (
	"net/url"
	"strings"
	"testing"
)

func goodVLESS() VLESSConfig {
	return VLESSConfig{
		UUID:      "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		Domain:    "example.com",
		Port:      443,
		PublicKey: "abcDEF_-1234567890",
		ShortID:   "deadbeef",
		Mode:      "vision",
		Label:     "home-stealth",
	}
}

func TestVLESSURIVision(t *testing.T) {
	u, err := VLESSURI(goodVLESS())
	if err != nil {
		t.Fatalf("VLESSURI: %v", err)
	}
	if !strings.HasPrefix(u, "vless://") {
		t.Fatalf("scheme: %s", u)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse: %v (raw=%q)", err, u)
	}
	if parsed.Host != "example.com:443" {
		t.Errorf("host: %s", parsed.Host)
	}
	q := parsed.Query()
	for k, want := range map[string]string{
		"encryption": "none",
		"security":   "reality",
		"sni":        "example.com",
		"pbk":        "abcDEF_-1234567890",
		"sid":        "deadbeef",
		"fp":         "chrome",
		"type":       "tcp",
		"flow":       "xtls-rprx-vision",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
	if parsed.Fragment != "home-stealth" {
		t.Errorf("fragment: %q", parsed.Fragment)
	}
}

func TestVLESSURIXHTTP(t *testing.T) {
	c := goodVLESS()
	c.Mode = "xhttp"
	c.XHTTPPath = "/de/ad/be/ef"
	u, err := VLESSURI(c)
	if err != nil {
		t.Fatalf("VLESSURI: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("type") != "xhttp" {
		t.Errorf("type=%q", q.Get("type"))
	}
	if q.Get("path") != "/de/ad/be/ef" {
		t.Errorf("path=%q", q.Get("path"))
	}
	if q.Get("flow") != "" {
		t.Errorf("flow must be empty in xhttp mode, got %q", q.Get("flow"))
	}
}

func TestVLESSURIRejectsBadInput(t *testing.T) {
	mut := func(f func(*VLESSConfig)) VLESSConfig {
		c := goodVLESS()
		f(&c)
		return c
	}
	cases := []struct {
		name string
		c    VLESSConfig
	}{
		{"empty UUID", mut(func(c *VLESSConfig) { c.UUID = "" })},
		{"empty domain", mut(func(c *VLESSConfig) { c.Domain = "" })},
		{"bad port low", mut(func(c *VLESSConfig) { c.Port = 0 })},
		{"bad port high", mut(func(c *VLESSConfig) { c.Port = 70000 })},
		{"empty pubkey", mut(func(c *VLESSConfig) { c.PublicKey = "" })},
		{"empty shortid", mut(func(c *VLESSConfig) { c.ShortID = "" })},
		{"unknown mode", mut(func(c *VLESSConfig) { c.Mode = "weird" })},
		{"xhttp missing path", mut(func(c *VLESSConfig) { c.Mode = "xhttp"; c.XHTTPPath = "" })},
		{"xhttp relative path", mut(func(c *VLESSConfig) { c.Mode = "xhttp"; c.XHTTPPath = "deadbeef" })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VLESSURI(tc.c); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNaiveURI(t *testing.T) {
	u, err := NaiveURI(NaiveConfig{
		Username: "alice",
		Password: "p@ss word",
		Domain:   "example.com",
		Port:     443,
		Label:    "naive home",
	})
	if err != nil {
		t.Fatalf("NaiveURI: %v", err)
	}
	if !strings.HasPrefix(u, "naive+https://") {
		t.Fatalf("scheme: %s", u)
	}
	if !strings.Contains(u, "alice:") {
		t.Errorf("username missing: %s", u)
	}
	// Password contains '@' and space — must be percent-encoded.
	if !strings.Contains(u, "p%40ss+word") && !strings.Contains(u, "p%40ss%20word") {
		t.Errorf("password not percent-encoded: %s", u)
	}
	if !strings.Contains(u, "@example.com:443") {
		t.Errorf("host segment: %s", u)
	}
	if !strings.Contains(u, "padding=true") {
		t.Errorf("padding=true missing: %s", u)
	}
	if !strings.Contains(u, "#naive%20home") {
		t.Errorf("label fragment: %s", u)
	}
}

func TestNaiveURIRejectsBadInput(t *testing.T) {
	cases := []NaiveConfig{
		{Domain: "example.com", Port: 443, Username: "", Password: "p"},
		{Domain: "example.com", Port: 443, Username: "u", Password: ""},
		{Domain: "", Port: 443, Username: "u", Password: "p"},
		{Domain: "example.com", Port: 0, Username: "u", Password: "p"},
		{Domain: "example.com", Port: 70000, Username: "u", Password: "p"},
	}
	for i, c := range cases {
		if _, err := NaiveURI(c); err == nil {
			t.Errorf("case %d: expected error: %+v", i, c)
		}
	}
}
