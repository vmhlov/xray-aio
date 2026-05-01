package subscribe

import (
	"strings"
	"testing"
)

func TestRenderPlainText(t *testing.T) {
	body, err := RenderPlainText(Bundle{
		VLESSURIs: []string{"vless://aaa", "vless://bbb"},
		NaiveURIs: []string{"naive+https://ccc"},
	})
	if err != nil {
		t.Fatalf("RenderPlainText: %v", err)
	}
	want := "vless://aaa\nvless://bbb\nnaive+https://ccc\n"
	if body != want {
		t.Fatalf("got %q want %q", body, want)
	}
}

func TestRenderPlainTextRejectsEmpty(t *testing.T) {
	if _, err := RenderPlainText(Bundle{}); err == nil {
		t.Fatal("expected error on empty bundle")
	}
}

func TestRenderHTML(t *testing.T) {
	out, err := RenderHTML(Bundle{
		Label:     "xray-aio test",
		VLESSURIs: []string{"vless://uuid@example.com:443?type=tcp"},
		NaiveURIs: []string{"naive+https://u:p@example.com:443"},
	})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, want := range []string{
		"<title>xray-aio test subscription</title>",
		"VLESS REALITY",
		"NaïveProxy",
		"vless://uuid@example.com:443?type=tcp",
		// '+' is HTML-encoded to &#43; in text/attr context by Go's
		// html/template — that's correct (browsers render it back).
		"naive&#43;https://u:p@example.com:443",
		"happ://add/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestRenderHTMLEscapesURIs verifies that Go's html/template escapes
// hostile content in URIs so it cannot break out of the <code>/<a>
// contexts.
func TestRenderHTMLEscapesURIs(t *testing.T) {
	hostile := `vless://uid@example.com?</code><script>alert(1)</script>`
	out, err := RenderHTML(Bundle{VLESSURIs: []string{hostile}})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatalf("hostile content not escaped:\n%s", out)
	}
}

func TestRenderPlainTextIncludesHysteria2(t *testing.T) {
	body, err := RenderPlainText(Bundle{
		VLESSURIs:     []string{"vless://aaa"},
		NaiveURIs:     []string{"naive+https://bbb"},
		Hysteria2URIs: []string{"hysteria2://pw@example.com:443/?sni=example.com&insecure=0"},
	})
	if err != nil {
		t.Fatalf("RenderPlainText: %v", err)
	}
	want := "vless://aaa\nnaive+https://bbb\nhysteria2://pw@example.com:443/?sni=example.com&insecure=0\n"
	if body != want {
		t.Fatalf("got %q want %q", body, want)
	}
}

func TestRenderHTMLIncludesHysteria2(t *testing.T) {
	out, err := RenderHTML(Bundle{
		Label:         "xray-aio test",
		Hysteria2URIs: []string{"hysteria2://pw@example.com:443/?sni=example.com&insecure=0#tag"},
	})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, want := range []string{
		"<h2>Hysteria 2</h2>",
		"hysteria2://pw@example.com:443/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderHTMLDefaultLabel(t *testing.T) {
	out, err := RenderHTML(Bundle{VLESSURIs: []string{"vless://x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<title>xray-aio subscription</title>") {
		t.Fatalf("default label missing:\n%s", out)
	}
}

func TestRenderHTMLIncludesAmneziaWG(t *testing.T) {
	conf := "[Interface]\nPrivateKey = peerpriv\nAddress = 10.66.66.2/32\nDNS = 1.1.1.1\nMTU = 1380\n"
	out, err := RenderHTML(Bundle{
		Label: "xray-aio test",
		AmneziaWGs: []AmneziaWGEntry{{
			Label:        "vmh-aio.site (AmneziaWG)",
			Conf:         conf,
			ConfURL:      "awg0.conf",
			ConfFilename: "awg0.conf",
			QRURL:        "awg0.png",
		}},
	})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, want := range []string{
		"<h2>AmneziaWG</h2>",
		"vmh-aio.site (AmneziaWG)",
		"<pre><code>",
		"PrivateKey = peerpriv",
		`href="awg0.conf"`,
		`download="awg0.conf"`,
		`src="awg0.png"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderHTMLAmneziaWGEscapesConfText(t *testing.T) {
	hostile := "[Interface]\nFakeKey = </code><script>alert(1)</script>\n"
	out, err := RenderHTML(Bundle{
		AmneziaWGs: []AmneziaWGEntry{{
			Conf:         hostile,
			ConfURL:      "awg0.conf",
			ConfFilename: "awg0.conf",
		}},
	})
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatalf("hostile conf content not escaped:\n%s", out)
	}
}

func TestRenderPlainTextOmitsAmneziaWG(t *testing.T) {
	body, err := RenderPlainText(Bundle{
		NaiveURIs: []string{"naive+https://u:p@example.com:443"},
		AmneziaWGs: []AmneziaWGEntry{{
			Conf:         "[Interface]\nPrivateKey = peerpriv\n",
			ConfFilename: "awg0.conf",
		}},
	})
	if err != nil {
		t.Fatalf("RenderPlainText: %v", err)
	}
	if strings.Contains(body, "PrivateKey") || strings.Contains(body, "[Interface]") {
		t.Errorf("AmneziaWG conf must not leak into plain text:\n%s", body)
	}
	want := "naive+https://u:p@example.com:443\n"
	if body != want {
		t.Errorf("got %q want %q", body, want)
	}
}

// AmneziaWG-only bundles have no URIs to advertise (Naive is
// always co-located with AmneziaWG in the home-vpn profile, but
// at the subscribe layer we treat the cases independently).
// Plain text should reject them — clients that fetch ?plain=1
// don't know how to consume a multi-line .conf.
func TestRenderPlainTextRejectsAmneziaWGOnly(t *testing.T) {
	_, err := RenderPlainText(Bundle{
		AmneziaWGs: []AmneziaWGEntry{{Conf: "x"}},
	})
	if err == nil {
		t.Fatal("expected error: AmneziaWG-only bundle has no URIs for plain.txt")
	}
}
