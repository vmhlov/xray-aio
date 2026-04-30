package hysteria2

import (
	"net/url"
	"strings"
	"testing"
)

func TestRenderURIDefaults(t *testing.T) {
	got, err := RenderURI(URIInputs{
		Domain:   "vpn.example.com",
		Password: "s3cret",
	})
	if err != nil {
		t.Fatalf("RenderURI: %v", err)
	}
	want := "hysteria2://s3cret@vpn.example.com:443/?insecure=0&sni=vpn.example.com"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRenderURIHonoursOverrides(t *testing.T) {
	got, err := RenderURI(URIInputs{
		Domain:   "vpn.example.com",
		Port:     11443,
		Password: "s3cret",
		SNI:      "decoy.example.com",
		Insecure: true,
		Tag:      "vpn.example.com (HY2)",
	})
	if err != nil {
		t.Fatalf("RenderURI: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("URI not a valid URL: %v\n%s", err, got)
	}
	if u.Scheme != "hysteria2" {
		t.Errorf("scheme = %q, want hysteria2", u.Scheme)
	}
	if u.User.Username() != "s3cret" {
		t.Errorf("user = %q, want s3cret", u.User.Username())
	}
	if u.Host != "vpn.example.com:11443" {
		t.Errorf("host = %q, want vpn.example.com:11443", u.Host)
	}
	if u.Query().Get("sni") != "decoy.example.com" {
		t.Errorf("sni = %q, want decoy.example.com", u.Query().Get("sni"))
	}
	if u.Query().Get("insecure") != "1" {
		t.Errorf("insecure = %q, want 1", u.Query().Get("insecure"))
	}
	if u.Fragment != "vpn.example.com (HY2)" {
		t.Errorf("fragment = %q, want %q", u.Fragment, "vpn.example.com (HY2)")
	}
}

func TestRenderURIRejectsMissingFields(t *testing.T) {
	cases := []URIInputs{
		{Password: "x"},
		{Domain: "vpn.example.com"},
	}
	for i, in := range cases {
		_, err := RenderURI(in)
		if err == nil {
			t.Errorf("case %d: expected error, got nil for %+v", i, in)
		}
	}
}

func TestRenderURIPercentEncodesPasswordWithSpecials(t *testing.T) {
	got, err := RenderURI(URIInputs{
		Domain:   "vpn.example.com",
		Password: "s3:cret/ok",
	})
	if err != nil {
		t.Fatalf("RenderURI: %v", err)
	}
	// `:` and `/` both need percent-encoding in the userinfo
	// component (RFC 3986 §3.2.1). net/url does this for us.
	if !strings.Contains(got, "s3%3Acret%2Fok") {
		t.Errorf("password not percent-encoded:\n%s", got)
	}
}
