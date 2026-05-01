package orchestrator

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/transport"
)

// awgRand returns a math/rand-backed io.Reader. Plain
// deterministicReader (counting bytes) hits a pathological case in
// the obfuscation generator's H1..H4 distinct-uint32 sampling — the
// counter happens to land on values in {1,2,3,4} repeatedly,
// stretching the rejection loop. A proper PRNG avoids that.
func awgRand(seed int64) *rand.Rand { return rand.New(rand.NewSource(seed)) }

func TestProfileNeedsAmneziaWG(t *testing.T) {
	t.Parallel()

	if !profileNeedsAmneziaWG("home-vpn") {
		t.Error("home-vpn should need amneziawg")
	}
	if profileNeedsAmneziaWG("home-stealth") {
		t.Error("home-stealth should NOT need amneziawg")
	}
	if profileNeedsAmneziaWG("home-mobile") {
		t.Error("home-mobile should NOT need amneziawg")
	}
	if profileNeedsAmneziaWG("nope") {
		t.Error("unknown profile should NOT need amneziawg")
	}
}

func TestProfileNeedsXray(t *testing.T) {
	t.Parallel()

	if !profileNeedsXray("home-stealth") {
		t.Error("home-stealth should need xray")
	}
	if !profileNeedsXray("home-mobile") {
		t.Error("home-mobile should need xray")
	}
	if profileNeedsXray("home-vpn") {
		t.Error("home-vpn should NOT need xray")
	}
}

func TestResolveProfileHomeVPN(t *testing.T) {
	t.Parallel()

	p, err := ResolveProfile("home-vpn")
	if err != nil {
		t.Fatalf("ResolveProfile(home-vpn): %v", err)
	}
	if p.Name != "home-vpn" {
		t.Errorf("Name: %q", p.Name)
	}
	got := p.Transports
	if len(got) != 2 || got[0] != "naive" || got[1] != "amneziawg" {
		t.Errorf("Transports: %v (want [naive amneziawg])", got)
	}
}

func TestGeneratePlanHomeVPNPopulatesAmneziaWG(t *testing.T) {
	t.Parallel()

	ps, err := generatePlan(InstallOptions{
		Profile: "home-vpn",
		Domain:  "vpn.example.com",
	}, awgRand(1))
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Xray != nil {
		t.Errorf("Xray must be nil for home-vpn, got %+v", ps.Xray)
	}
	if ps.Hysteria2 != nil {
		t.Errorf("Hysteria2 must be nil for home-vpn, got %+v", ps.Hysteria2)
	}
	if ps.Naive == nil {
		t.Fatal("Naive must be populated for home-vpn (it hosts /sub/)")
	}
	awg := ps.AmneziaWG
	if awg == nil {
		t.Fatal("AmneziaWG must be populated for home-vpn")
	}
	if awg.ServerPrivateKey == "" || awg.ServerPublicKey == "" {
		t.Errorf("server key empty: priv=%q pub=%q", awg.ServerPrivateKey, awg.ServerPublicKey)
	}
	if awg.PeerPrivateKey == "" || awg.PeerPublicKey == "" {
		t.Errorf("peer key empty: priv=%q pub=%q", awg.PeerPrivateKey, awg.PeerPublicKey)
	}
	if awg.PresharedKey == "" {
		t.Error("PresharedKey empty")
	}
	if awg.ServerPrivateKey == awg.PeerPrivateKey {
		t.Error("server and peer private keys must differ")
	}
	if awg.ListenPort != 51842 {
		t.Errorf("ListenPort default mismatch: %d", awg.ListenPort)
	}
	if awg.ServerAddress != "10.66.66.1/24" {
		t.Errorf("ServerAddress default mismatch: %q", awg.ServerAddress)
	}
	if awg.PeerAddress != "10.66.66.2/32" {
		t.Errorf("PeerAddress default mismatch: %q", awg.PeerAddress)
	}
	if awg.MTU != 1380 {
		t.Errorf("MTU default mismatch: %d", awg.MTU)
	}
	if awg.DNS != "1.1.1.1" {
		t.Errorf("DNS default mismatch: %q", awg.DNS)
	}
	// Obfuscation: cheap sanity on shape; the package's own
	// keys_test.go validates the full constraint matrix.
	if awg.Jc < 1 || awg.Jc > 128 {
		t.Errorf("Jc out of range: %d", awg.Jc)
	}
	if awg.Jmin < 0 || awg.Jmin > awg.Jmax {
		t.Errorf("Jmin/Jmax: %d > %d", awg.Jmin, awg.Jmax)
	}
	if awg.S1 == 0 || awg.S2 == 0 {
		t.Error("S1/S2 must be non-zero")
	}
	headers := []uint32{awg.H1, awg.H2, awg.H3, awg.H4}
	for _, h := range headers {
		if h <= 4 {
			t.Errorf("magic header %d collides with WireGuard message-types {1..4}", h)
		}
	}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			if headers[i] == headers[j] {
				t.Errorf("magic headers must be distinct: H[%d]=H[%d]=%d", i+1, j+1, headers[i])
			}
		}
	}
}

func TestGeneratePlanHomeVPNHonoursOverrides(t *testing.T) {
	t.Parallel()

	ps, err := generatePlan(InstallOptions{
		Profile:                "home-vpn",
		Domain:                 "vpn.example.com",
		AmneziaWGListenPort:    53000,
		AmneziaWGServerAddress: "10.10.0.1/24",
		AmneziaWGPeerAddress:   "10.10.0.42/32",
		AmneziaWGMTU:           1420,
		AmneziaWGDNS:           "9.9.9.9",
	}, awgRand(2))
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	awg := ps.AmneziaWG
	if awg.ListenPort != 53000 {
		t.Errorf("ListenPort: %d", awg.ListenPort)
	}
	if awg.ServerAddress != "10.10.0.1/24" {
		t.Errorf("ServerAddress: %q", awg.ServerAddress)
	}
	if awg.PeerAddress != "10.10.0.42/32" {
		t.Errorf("PeerAddress: %q", awg.PeerAddress)
	}
	if awg.MTU != 1420 {
		t.Errorf("MTU: %d", awg.MTU)
	}
	if awg.DNS != "9.9.9.9" {
		t.Errorf("DNS: %q", awg.DNS)
	}
}

func TestGeneratePlanHomeStealthOmitsAmneziaWG(t *testing.T) {
	t.Parallel()

	ps, err := generatePlan(InstallOptions{
		Profile: "home-stealth",
		Domain:  "example.com",
	}, awgRand(3))
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.AmneziaWG != nil {
		t.Errorf("AmneziaWG must be nil for home-stealth, got %+v", ps.AmneziaWG)
	}
}

func TestBuildTransportOptionsAmneziaWG(t *testing.T) {
	t.Parallel()

	ps := &ProfileState{
		Profile: "home-vpn",
		Domain:  "vpn.example.com",
		AmneziaWG: &AmneziaWGState{
			ServerPrivateKey: "srv-priv",
			ServerPublicKey:  "srv-pub",
			PeerPrivateKey:   "peer-priv",
			PeerPublicKey:    "peer-pub",
			PresharedKey:     "psk",
			ListenPort:       51842,
			ServerAddress:    "10.66.66.1/24",
			PeerAddress:      "10.66.66.2/32",
			MTU:              1380,
			DNS:              "1.1.1.1",
			Jc:               5, Jmin: 50, Jmax: 1000,
			S1: 80, S2: 60,
			H1: 0xAAAAAAAA, H2: 0xBBBBBBBB, H3: 0xCCCCCCCC, H4: 0xDDDDDDDD,
		},
	}
	opts, err := buildTransportOptions("amneziawg", ps)
	if err != nil {
		t.Fatalf("buildTransportOptions: %v", err)
	}
	if opts.Domain != "vpn.example.com" {
		t.Errorf("Domain: %q", opts.Domain)
	}
	want := map[string]any{
		"amneziawg.private_key":     "srv-priv",
		"amneziawg.peer_public_key": "peer-pub",
		"amneziawg.peer_preshared":  "psk",
		"amneziawg.server_address":  "10.66.66.1/24",
		"amneziawg.peer_address":    "10.66.66.2/32",
		"amneziawg.listen_port":     51842,
		"amneziawg.mtu":             1380,
		"amneziawg.dns":             "1.1.1.1",
		"amneziawg.jc":              5,
		"amneziawg.jmin":            50,
		"amneziawg.jmax":            1000,
		"amneziawg.s1":              80,
		"amneziawg.s2":              60,
		"amneziawg.h1":              uint32(0xAAAAAAAA),
		"amneziawg.h2":              uint32(0xBBBBBBBB),
		"amneziawg.h3":              uint32(0xCCCCCCCC),
		"amneziawg.h4":              uint32(0xDDDDDDDD),
	}
	for k, v := range want {
		got, ok := opts.Extra[k]
		if !ok {
			t.Errorf("missing %q in Extra", k)
			continue
		}
		if got != v {
			t.Errorf("%q: got %v (%T), want %v (%T)", k, got, got, v, v)
		}
	}
	// Server public key MUST NOT leak to the transport — it's
	// for the peer-side .conf only, rendered in the subscription
	// bundle (PR #26).
	if _, leaked := opts.Extra["amneziawg.server_public_key"]; leaked {
		t.Error("server public key must not be sent to the transport")
	}
}

func TestBuildTransportOptionsAmneziaWGStateMissing(t *testing.T) {
	t.Parallel()

	ps := &ProfileState{Profile: "home-vpn", Domain: "x.test"}
	_, err := buildTransportOptions("amneziawg", ps)
	if err == nil {
		t.Fatal("expected error when AmneziaWG state missing")
	}
	if !strings.Contains(err.Error(), "amneziawg state missing") {
		t.Errorf("error message: %q", err.Error())
	}
}

func TestInstallHomeVPNUsesNaiveAndAmneziaWGOnly(t *testing.T) {
	// Intentionally not t.Parallel(): Install threads its
	// StatePath through a process-wide env var (see install.go's
	// stateEnvVar handoff), so two parallel Install calls would
	// race on the path. Existing install_test.go follows the
	// same convention.
	rec := newRecordingTransports()
	tmp := t.TempDir()
	siteRoot := tmp + "/site"
	res, err := Install(context.Background(), InstallOptions{
		Profile:       "home-vpn",
		Domain:        "vpn.example.com",
		NaiveSiteRoot: siteRoot,
	}, Deps{
		Rand:         awgRand(7),
		PreflightFn:  successfulPreflight,
		NewTransport: rec.factory,
		Now:          func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) },
		StatePath:    tmp + "/state.json",
	})
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := rec.installed; len(got) != 2 || got[0] != "naive" || got[1] != "amneziawg" {
		t.Errorf("install order: %v (want [naive amneziawg])", got)
	}
	if res.State.Xray != nil {
		t.Errorf("home-vpn must not generate Xray state, got %+v", res.State.Xray)
	}
	if res.State.AmneziaWG == nil {
		t.Fatal("home-vpn must persist AmneziaWG state")
	}
	if len(res.Bundle.NaiveURIs) != 1 {
		t.Errorf("Bundle.NaiveURIs: %v", res.Bundle.NaiveURIs)
	}
	if len(res.Bundle.VLESSURIs) != 0 {
		t.Errorf("Bundle.VLESSURIs must be empty for home-vpn: %v", res.Bundle.VLESSURIs)
	}
	if len(res.Bundle.Hysteria2URIs) != 0 {
		t.Errorf("Bundle.Hysteria2URIs must be empty for home-vpn: %v", res.Bundle.Hysteria2URIs)
	}
	if len(res.Bundle.AmneziaWGs) != 1 {
		t.Fatalf("Bundle.AmneziaWGs: got %d, want 1", len(res.Bundle.AmneziaWGs))
	}
	entry := res.Bundle.AmneziaWGs[0]
	if entry.ConfFilename != "awg0.conf" || entry.QRURL != "awg0.png" {
		t.Errorf("entry filenames: %+v", entry)
	}
	if !strings.Contains(entry.Conf, "[Interface]") || !strings.Contains(entry.Conf, "Endpoint = vpn.example.com:") {
		t.Errorf("entry.Conf missing expected fields:\n%s", entry.Conf)
	}
	// Server private key MUST NOT appear in the peer-side .conf.
	if strings.Contains(entry.Conf, res.State.AmneziaWG.ServerPrivateKey) {
		t.Error("server private key leaked into peer .conf")
	}

	// Bundle dir on disk: index.html + plain.txt + awg0.conf + awg0.png.
	bundleDir := filepath.Join(siteRoot, "sub", res.State.Subscription.Token)
	for _, name := range []string{"index.html", "plain.txt", "awg0.conf", "awg0.png"} {
		fi, err := os.Stat(filepath.Join(bundleDir, name))
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if fi.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
	confBytes, err := os.ReadFile(filepath.Join(bundleDir, "awg0.conf"))
	if err != nil {
		t.Fatalf("read awg0.conf: %v", err)
	}
	if string(confBytes) != entry.Conf {
		t.Error("on-disk awg0.conf does not match Bundle.AmneziaWGs[0].Conf")
	}
	// QR PNG must be a real PNG (8-byte magic header).
	pngBytes, err := os.ReadFile(filepath.Join(bundleDir, "awg0.png"))
	if err != nil {
		t.Fatalf("read awg0.png: %v", err)
	}
	if len(pngBytes) < 8 || string(pngBytes[:8]) != "\x89PNG\r\n\x1a\n" {
		t.Errorf("awg0.png is not a valid PNG (first 8 bytes: %x)", pngBytes[:min(8, len(pngBytes))])
	}
	// HTML page must reference both relative URLs.
	htmlBytes, err := os.ReadFile(filepath.Join(bundleDir, "index.html"))
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	html := string(htmlBytes)
	for _, want := range []string{`href="awg0.conf"`, `src="awg0.png"`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html missing %q", want)
		}
	}
}

func TestInstallHomeVPNReinstallPreservesAmneziaWGKeys(t *testing.T) {
	// Intentionally not t.Parallel(): see
	// TestInstallHomeVPNUsesNaiveAndAmneziaWGOnly above.
	rec := newRecordingTransports()
	tmp := t.TempDir()
	siteRoot := tmp + "/site"
	statePath := tmp + "/state.json"
	now := func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) }

	// First install — populates state.
	first, err := Install(context.Background(), InstallOptions{
		Profile:       "home-vpn",
		Domain:        "vpn.example.com",
		NaiveSiteRoot: siteRoot,
	}, Deps{
		Rand:         awgRand(11),
		PreflightFn:  successfulPreflight,
		NewTransport: rec.factory,
		Now:          now,
		StatePath:    statePath,
	})
	if err != nil {
		t.Fatalf("first Install: %v", err)
	}
	pre := *first.State.AmneziaWG

	// Second install — re-runs with a different RNG. Crypto
	// material MUST stay the same; ergonomic knobs may change.
	second, err := Install(context.Background(), InstallOptions{
		Profile:             "home-vpn",
		Domain:              "vpn.example.com",
		NaiveSiteRoot:       siteRoot,
		AmneziaWGListenPort: 53999,
	}, Deps{
		Rand:         awgRand(22),
		PreflightFn:  successfulPreflight,
		NewTransport: rec.factory,
		Now:          now,
		StatePath:    statePath,
	})
	if err != nil {
		t.Fatalf("second Install: %v", err)
	}
	post := *second.State.AmneziaWG
	if pre.ServerPrivateKey != post.ServerPrivateKey {
		t.Error("ServerPrivateKey must persist across re-installs")
	}
	if pre.PeerPrivateKey != post.PeerPrivateKey {
		t.Error("PeerPrivateKey must persist across re-installs")
	}
	if pre.PresharedKey != post.PresharedKey {
		t.Error("PresharedKey must persist across re-installs")
	}
	if pre.Jc != post.Jc || pre.S1 != post.S1 || pre.H1 != post.H1 {
		t.Error("obfuscation params must persist across re-installs")
	}
	if post.ListenPort != 53999 {
		t.Errorf("ListenPort override not honoured: got %d, want 53999", post.ListenPort)
	}
}

// recordingTransports is a tiny test seam that builds a fake
// transport.Transport for each registry name Install asks for and
// records the install order. Probe/Status/Stop/Uninstall are
// no-ops.
type recordingTransports struct {
	installed []string
}

func newRecordingTransports() *recordingTransports {
	return &recordingTransports{}
}

func (r *recordingTransports) factory(name string) (transport.Transport, error) {
	return &recordingTransport{name: name, parent: r}, nil
}

type recordingTransport struct {
	name   string
	parent *recordingTransports
}

func (t *recordingTransport) Name() string { return t.name }
func (t *recordingTransport) Install(_ context.Context, _ transport.Options) error {
	t.parent.installed = append(t.parent.installed, t.name)
	return nil
}
func (t *recordingTransport) Start(_ context.Context) error { return nil }
func (t *recordingTransport) Stop(_ context.Context) error  { return nil }
func (t *recordingTransport) Status(_ context.Context) (transport.Status, error) {
	return transport.Status{Running: true}, nil
}
func (t *recordingTransport) Probe(_ context.Context) (transport.ProbeResult, error) {
	return transport.ProbeResult{OK: true}, nil
}
func (t *recordingTransport) Uninstall(_ context.Context) error { return nil }

func successfulPreflight(_ context.Context) (preflight.Result, error) {
	return preflight.Result{
		Checks: []preflight.Check{{Name: "ok", Status: preflight.StatusOK}},
	}, nil
}
