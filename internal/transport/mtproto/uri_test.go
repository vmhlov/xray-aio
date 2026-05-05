package mtproto

import (
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

const testSecret = "deadbeefcafebabedeadbeefcafebabe"

func TestRenderURIRequiresDomain(t *testing.T) {
	_, err := RenderURI(URIInputs{Secret: testSecret})
	if err == nil {
		t.Fatalf("want error when Domain empty")
	}
}

func TestRenderURIRequiresValidSecret(t *testing.T) {
	_, err := RenderURI(URIInputs{Domain: "vpn.example.com", Secret: "short"})
	if err == nil {
		t.Fatalf("want error when Secret invalid")
	}
}

func TestRenderURIDefaultsEE(t *testing.T) {
	got, err := RenderURI(URIInputs{Domain: "vpn.example.com", Secret: testSecret})
	if err != nil {
		t.Fatalf("RenderURI: %v", err)
	}
	if !strings.HasPrefix(got, "tg://proxy?") {
		t.Fatalf("unexpected scheme; got %q", got)
	}
	q, err := parseQuery(strings.TrimPrefix(got, "tg://proxy?"))
	if err != nil {
		t.Fatalf("query parse: %v", err)
	}
	if q.Get("server") != "vpn.example.com" {
		t.Errorf("server=%q", q.Get("server"))
	}
	if q.Get("port") != "8883" {
		t.Errorf("port=%q, want default 8883", q.Get("port"))
	}
	// secret = "ee" + hex(secret_bytes) + hex(tls_domain)
	wantTLS := hex.EncodeToString([]byte(DefaultTLSDomain))
	wantSecret := "ee" + testSecret + wantTLS
	if q.Get("secret") != wantSecret {
		t.Errorf("secret=%q, want %q", q.Get("secret"), wantSecret)
	}
}

func TestRenderURIOverrides(t *testing.T) {
	got, err := RenderURI(URIInputs{
		Domain:    "vpn.example.com",
		Port:      9443,
		Secret:    "CAFEBABECAFEBABECAFEBABECAFEBABE",
		TLSDomain: "www.cloudflare.com",
	})
	if err != nil {
		t.Fatalf("RenderURI: %v", err)
	}
	q, err := parseQuery(strings.TrimPrefix(got, "tg://proxy?"))
	if err != nil {
		t.Fatalf("query parse: %v", err)
	}
	if q.Get("port") != "9443" {
		t.Errorf("port=%q", q.Get("port"))
	}
	if !strings.HasPrefix(q.Get("secret"), "ee") {
		t.Errorf("secret missing ee prefix: %q", q.Get("secret"))
	}
	if !strings.Contains(q.Get("secret"), hex.EncodeToString([]byte("www.cloudflare.com"))) {
		t.Errorf("secret missing tls_domain hex suffix: %q", q.Get("secret"))
	}
	if strings.Contains(q.Get("secret"), "CAFEBABE") {
		t.Errorf("secret leaked upper-case: %q", q.Get("secret"))
	}
}

func TestRenderHTTPSURI(t *testing.T) {
	got, err := RenderHTTPSURI(URIInputs{Domain: "vpn.example.com", Secret: testSecret})
	if err != nil {
		t.Fatalf("RenderHTTPSURI: %v", err)
	}
	if !strings.HasPrefix(got, "https://t.me/proxy?") {
		t.Fatalf("unexpected scheme; got %q", got)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Host != "t.me" || u.Path != "/proxy" {
		t.Fatalf("wrong host/path: %s %s", u.Host, u.Path)
	}
	if !strings.HasPrefix(u.Query().Get("secret"), "ee"+testSecret) {
		t.Errorf("https secret missing ee+hex: %q", u.Query().Get("secret"))
	}
}

func parseQuery(raw string) (url.Values, error) {
	return url.ParseQuery(raw)
}
