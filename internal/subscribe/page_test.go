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
