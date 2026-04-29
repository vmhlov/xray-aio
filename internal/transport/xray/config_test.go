package xray

import (
	"encoding/json"
	"strings"
	"testing"
)

// validConfig builds a Config that passes validate() so tests can mutate
// one field at a time without re-stating every dependency.
func validConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Domain:     "example.com",
		Dest:       "127.0.0.1:8443",
		UUID:       "deadbeef-1234-4567-89ab-0123456789ab",
		PrivateKey: "uPRDuVscbHiK4N0wkgAcXSiPCnMltYWQs7H8w8q7eFw",
		PublicKey:  "kqkdvDhbE0c4mSMtRr_4l8m4Mb1iZ6Sxg2Tr9hJqW2g",
		ShortIDs:   []string{"deadbeef"},
	}
}

func TestRenderVisionDefault(t *testing.T) {
	out, err := Render(validConfig(t))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}

	inbound := got["inbounds"].([]any)[0].(map[string]any)
	if inbound["protocol"].(string) != "vless" {
		t.Errorf("protocol: %v", inbound["protocol"])
	}
	if inbound["port"].(float64) != float64(DefaultListenPort) {
		t.Errorf("port: %v", inbound["port"])
	}

	stream := inbound["streamSettings"].(map[string]any)
	if stream["network"].(string) != "tcp" {
		t.Errorf("Vision network must be tcp, got %v", stream["network"])
	}
	if stream["security"].(string) != "reality" {
		t.Errorf("security: %v", stream["security"])
	}

	settings := inbound["settings"].(map[string]any)
	clients := settings["clients"].([]any)
	client := clients[0].(map[string]any)
	if client["flow"].(string) != "xtls-rprx-vision" {
		t.Errorf("flow: %v", client["flow"])
	}

	reality := stream["realitySettings"].(map[string]any)
	if reality["dest"].(string) != "127.0.0.1:8443" {
		t.Errorf("dest: %v", reality["dest"])
	}
	names := reality["serverNames"].([]any)
	if len(names) != 1 || names[0].(string) != "example.com" {
		t.Errorf("serverNames: %v", names)
	}
}

func TestRenderXHTTP(t *testing.T) {
	c := validConfig(t)
	c.Mode = ModeXHTTP
	c.XHTTPPath = "/abc12345"
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	stream := got["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if stream["network"].(string) != "xhttp" {
		t.Fatalf("network: %v", stream["network"])
	}
	xhttp := stream["xhttpSettings"].(map[string]any)
	if xhttp["path"].(string) != "/abc12345" {
		t.Fatalf("xhttp path: %v", xhttp["path"])
	}

	// Vision flow must NOT be set in XHTTP mode.
	client := got["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
	if _, ok := client["flow"]; ok {
		t.Fatalf("XHTTP must not carry vision flow: %v", client)
	}
}

func TestRenderXHTTPDerivesPathFromShortID(t *testing.T) {
	c := validConfig(t)
	c.Mode = ModeXHTTP
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, `"path": "/deadbeef"`) {
		t.Fatalf("expected derived path, got:\n%s", out)
	}
}

func TestRenderRejectsBadInput(t *testing.T) {
	mut := func(f func(*Config)) Config {
		c := validConfig(t)
		f(&c)
		return c
	}
	cases := []struct {
		name string
		c    Config
	}{
		{"empty domain", mut(func(c *Config) { c.Domain = "" })},
		{"port too high", mut(func(c *Config) { c.ListenPort = 100000 })},
		{"port negative", mut(func(c *Config) { c.ListenPort = -1 })},
		{"dest empty", mut(func(c *Config) { c.Dest = "" })},
		{"dest no port", mut(func(c *Config) { c.Dest = "127.0.0.1" })},
		{"uuid wrong shape", mut(func(c *Config) { c.UUID = "not-a-uuid" })},
		{"missing keys", mut(func(c *Config) { c.PrivateKey = "" })},
		{"no shortIDs", mut(func(c *Config) { c.ShortIDs = nil })},
		{"shortID upper", mut(func(c *Config) { c.ShortIDs = []string{"DEADBEEF"} })},
		{"shortID nonhex", mut(func(c *Config) { c.ShortIDs = []string{"zzzz"} })},
		{"unknown mode", mut(func(c *Config) { c.Mode = "amazing" })},
		{"xhttp empty path", mut(func(c *Config) { c.Mode = ModeXHTTP; c.XHTTPPath = "x"; c.ShortIDs = nil })},
		{"xhttp bad path", mut(func(c *Config) { c.Mode = ModeXHTTP; c.XHTTPPath = "no-slash" })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Render(tc.c); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRenderJSONRoundtrip(t *testing.T) {
	out, err := Render(validConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
}
