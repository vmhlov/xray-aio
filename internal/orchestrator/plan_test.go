package orchestrator

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vmhlov/xray-aio/internal/subscribe"
)

// deterministicReader yields a repeating byte sequence so tests get
// predictable secrets without needing crypto/rand.
type deterministicReader struct {
	seed byte
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.seed
		r.seed++
	}
	return len(p), nil
}

func TestGeneratePlanHappy(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	ps, err := generatePlan(InstallOptions{
		Profile: "home-stealth",
		Domain:  "example.com",
		Email:   "ops@example.com",
	}, rng)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Profile != "home-stealth" {
		t.Errorf("profile mismatch: %q", ps.Profile)
	}
	if ps.Domain != "example.com" {
		t.Errorf("domain mismatch: %q", ps.Domain)
	}
	if ps.Xray == nil || ps.Naive == nil || ps.Subscription == nil {
		t.Fatal("Xray/Naive/Subscription must be populated")
	}
	if len(ps.Xray.UUID) != 36 || strings.Count(ps.Xray.UUID, "-") != 4 {
		t.Errorf("Xray.UUID malformed: %q", ps.Xray.UUID)
	}
	if ps.Xray.PublicKey == "" || ps.Xray.PrivateKey == "" {
		t.Errorf("Xray keys empty: priv=%q pub=%q", ps.Xray.PrivateKey, ps.Xray.PublicKey)
	}
	if len(ps.Xray.ShortIDs) != 1 || len(ps.Xray.ShortIDs[0]) != 16 {
		t.Errorf("Xray.ShortIDs malformed: %v", ps.Xray.ShortIDs)
	}
	if ps.Xray.ListenPort != 443 {
		t.Errorf("Xray.ListenPort default mismatch: %d", ps.Xray.ListenPort)
	}
	if ps.Xray.Dest != "127.0.0.1:8443" {
		t.Errorf("Xray.Dest default mismatch: %q", ps.Xray.Dest)
	}
	if ps.Xray.Mode != "vision" {
		t.Errorf("Xray.Mode default mismatch: %q", ps.Xray.Mode)
	}
	if len(ps.Naive.Username) != 16 {
		t.Errorf("Naive.Username length: %d", len(ps.Naive.Username))
	}
	if len(ps.Naive.Password) != 32 {
		t.Errorf("Naive.Password length: %d", len(ps.Naive.Password))
	}
	if ps.Naive.ListenPort != 8444 {
		t.Errorf("Naive.ListenPort default mismatch: %d", ps.Naive.ListenPort)
	}
	secret, err := ps.Subscription.secretBytes()
	if err != nil {
		t.Fatalf("secretBytes: %v", err)
	}
	if len(secret) != subscribe.SecretBytes {
		t.Errorf("subscription secret length: %d (want %d)", len(secret), subscribe.SecretBytes)
	}
	id, err := subscribe.VerifyToken(secret, ps.Subscription.Token)
	if err != nil {
		t.Fatalf("token does not verify against secret: %v", err)
	}
	if id != "default" {
		t.Errorf("verified id: %q (want default)", id)
	}
}

func TestGeneratePlanHonoursOverrides(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	ps, err := generatePlan(InstallOptions{
		Profile:   "home-stealth",
		Domain:    "example.com",
		XrayPort:  10443,
		NaivePort: 11444,
		XrayDest:  "www.example-cdn.com:443",
	}, rng)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Xray.ListenPort != 10443 {
		t.Errorf("Xray.ListenPort: %d", ps.Xray.ListenPort)
	}
	if ps.Naive.ListenPort != 11444 {
		t.Errorf("Naive.ListenPort: %d", ps.Naive.ListenPort)
	}
	if ps.Xray.Dest != "www.example-cdn.com:443" {
		t.Errorf("Xray.Dest: %q", ps.Xray.Dest)
	}
}

func TestGeneratePlanRejectsEmptyDomain(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	if _, err := generatePlan(InstallOptions{Profile: "home-stealth"}, rng); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestGeneratePlanUUIDIsDeterministicGivenRNG(t *testing.T) {
	t.Parallel()

	// We intentionally only assert on UUID determinism. ecdh.X25519's
	// GenerateKey calls randutil.MaybeReadByte to discourage callers
	// from relying on a precise byte count, so x25519/short-id/naive
	// fields aren't byte-stable across runs even with identical RNG.
	rng1 := &deterministicReader{}
	rng2 := &deterministicReader{}
	a, err := generatePlan(InstallOptions{Profile: "home-stealth", Domain: "x.test"}, rng1)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := generatePlan(InstallOptions{Profile: "home-stealth", Domain: "x.test"}, rng2)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a.Xray.UUID != b.Xray.UUID {
		t.Errorf("identical RNG produced different UUIDs: %q vs %q", a.Xray.UUID, b.Xray.UUID)
	}
}

func TestGeneratePlanRejectsShortRandomness(t *testing.T) {
	t.Parallel()

	if _, err := generatePlan(InstallOptions{Profile: "home-stealth", Domain: "x.test"}, bytes.NewReader(nil)); err == nil {
		t.Fatal("expected error from empty rng")
	}
}

func TestGeneratePlanHomeMobileIncludesHysteria2(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	ps, err := generatePlan(InstallOptions{
		Profile: "home-mobile",
		Domain:  "example.com",
	}, rng)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Hysteria2 == nil {
		t.Fatal("Hysteria2 must be populated for home-mobile")
	}
	if ps.Hysteria2.Password == "" {
		t.Error("Hysteria2.Password empty")
	}
	if _, err := base64.RawURLEncoding.DecodeString(ps.Hysteria2.Password); err != nil {
		t.Errorf("Hysteria2.Password not RawURL b64: %v", err)
	}
	if ps.Hysteria2.ListenPort != 443 {
		t.Errorf("Hysteria2.ListenPort default mismatch: %d", ps.Hysteria2.ListenPort)
	}
	if ps.Hysteria2.MasqueradeURL != "https://example.com:8443" {
		t.Errorf("Hysteria2.MasqueradeURL default mismatch: %q (must use Domain so SNI matches Caddy's site definition)", ps.Hysteria2.MasqueradeURL)
	}
}

func TestGeneratePlanHomeStealthOmitsHysteria2(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	ps, err := generatePlan(InstallOptions{Profile: "home-stealth", Domain: "example.com"}, rng)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Hysteria2 != nil {
		t.Errorf("Hysteria2 must be nil for home-stealth, got %+v", ps.Hysteria2)
	}
}

func TestGeneratePlanHomeMobileHonoursHysteria2Overrides(t *testing.T) {
	t.Parallel()

	rng := &deterministicReader{}
	ps, err := generatePlan(InstallOptions{
		Profile:                "home-mobile",
		Domain:                 "example.com",
		Hysteria2Port:          12443,
		Hysteria2MasqueradeURL: "https://example-masq.test",
	}, rng)
	if err != nil {
		t.Fatalf("generatePlan: %v", err)
	}
	if ps.Hysteria2.ListenPort != 12443 {
		t.Errorf("Hysteria2.ListenPort: %d", ps.Hysteria2.ListenPort)
	}
	if ps.Hysteria2.MasqueradeURL != "https://example-masq.test" {
		t.Errorf("Hysteria2.MasqueradeURL: %q", ps.Hysteria2.MasqueradeURL)
	}
}

func TestSecretBytesRoundtrip(t *testing.T) {
	t.Parallel()

	want := bytes.Repeat([]byte{0xAB}, subscribe.SecretBytes)
	ps := &SubscriptionState{Secret: base64.RawURLEncoding.EncodeToString(want)}
	got, err := ps.secretBytes()
	if err != nil {
		t.Fatalf("secretBytes: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("roundtrip mismatch")
	}
}
