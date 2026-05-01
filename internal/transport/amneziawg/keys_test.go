package amneziawg

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
)

// seededReader returns a math/rand-backed reader that produces the
// same bytes for the same seed across runs. We can't use a
// constant-byte stream because the obfuscation generator does
// rejection sampling for distinct H1..H4 — repeating bytes would
// produce identical uint32 draws and burn through the test buffer
// in collision retries.
func seededReader(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

func TestGenerateX25519Deterministic(t *testing.T) {
	// Two readers with the same byte stream must produce the same
	// keypair. Production code uses crypto/rand; tests rely on
	// this property to make state.json round-trips deterministic.
	stream := bytes.Repeat([]byte{0x42}, 256)
	a, err := GenerateX25519FromReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("first generate: %v", err)
	}
	b, err := GenerateX25519FromReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("second generate: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %+v vs %+v", a, b)
	}
	// Decoded private key must be exactly 32 bytes (Curve25519 scalar).
	priv, err := base64.StdEncoding.DecodeString(a.Private)
	if err != nil {
		t.Fatalf("decode private: %v", err)
	}
	if len(priv) != 32 {
		t.Fatalf("private key length %d, want 32", len(priv))
	}
	pub, err := base64.StdEncoding.DecodeString(a.Public)
	if err != nil {
		t.Fatalf("decode public: %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("public key length %d, want 32", len(pub))
	}
	// Private and public must differ — clamp + scalar mult should
	// never yield identity for a 32-byte all-0x42 seed.
	if a.Private == a.Public {
		t.Fatal("private == public, scalar mult collapsed to identity")
	}
}

func TestGenerateX25519Production(t *testing.T) {
	// Smoke test the production crypto/rand path so the public
	// API isn't dead code outside test mocks.
	k, err := GenerateX25519()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if k.Private == "" || k.Public == "" {
		t.Fatalf("empty keys: %+v", k)
	}
	if !strings.HasSuffix(k.Private, "=") {
		t.Errorf("expected base64 padding on private key, got %q", k.Private)
	}
}

func TestGeneratePresharedKey(t *testing.T) {
	stream := bytes.Repeat([]byte{0x7e}, 64)
	a, err := GeneratePresharedKeyFromReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := GeneratePresharedKeyFromReader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}
	raw, err := base64.StdEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("psk length %d, want 32", len(raw))
	}
}

func TestObfuscationValidateAccepts(t *testing.T) {
	o := Obfuscation{
		Jc:   5,
		Jmin: 50,
		Jmax: 1000,
		S1:   100,
		S2:   100, // 100+56=156, 100+88=188; no collision
		H1:   0xAAAAAAAA,
		H2:   0xBBBBBBBB,
		H3:   0xCCCCCCCC,
		H4:   0xDDDDDDDD,
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("expected valid: %v", err)
	}
}

func TestObfuscationValidateRejects(t *testing.T) {
	base := Obfuscation{
		Jc:   5,
		Jmin: 50,
		Jmax: 1000,
		S1:   100,
		S2:   100,
		H1:   0xAAAAAAAA,
		H2:   0xBBBBBBBB,
		H3:   0xCCCCCCCC,
		H4:   0xDDDDDDDD,
	}
	cases := []struct {
		name string
		mut  func(*Obfuscation)
		want string
	}{
		{"jc-too-small", func(o *Obfuscation) { o.Jc = 0 }, "Jc"},
		{"jc-too-large", func(o *Obfuscation) { o.Jc = 200 }, "Jc"},
		{"jmin-negative", func(o *Obfuscation) { o.Jmin = -1 }, "Jmin"},
		{"jmin-over", func(o *Obfuscation) { o.Jmin = 2000 }, "Jmin"},
		{"jmax-below-jmin", func(o *Obfuscation) { o.Jmin = 100; o.Jmax = 50 }, "Jmax"},
		{"jmax-over", func(o *Obfuscation) { o.Jmax = 2000 }, "Jmax"},
		{"s1-too-small", func(o *Obfuscation) { o.S1 = 5 }, "S1"},
		{"s1-too-large", func(o *Obfuscation) { o.S1 = 200 }, "S1"},
		{"s2-too-small", func(o *Obfuscation) { o.S2 = 5 }, "S2"},
		{"s2-too-large", func(o *Obfuscation) { o.S2 = 200 }, "S2"},
		// 32+56 == 64+88 - 64? No: 32+56 = 88; 0+88 = 88. So S1=32, S2=0
		// would collide if S2=0 were legal, but S2 in [15,150]. Use
		// S1=20, S2=20-32=... pick S1=44, S2=12 (illegal lower-bound).
		// Easier: S1=132, S2=100. 132+56=188; 100+88=188 → collision.
		{"s-collision", func(o *Obfuscation) { o.S1 = 132; o.S2 = 100 }, "S1+56"},
		{"h1-eq-wg-msgtype", func(o *Obfuscation) { o.H1 = 1 }, "H1"},
		{"h2-eq-wg-msgtype", func(o *Obfuscation) { o.H2 = 4 }, "H2"},
		{"h3-eq-wg-msgtype", func(o *Obfuscation) { o.H3 = 2 }, "H3"},
		{"h4-eq-wg-msgtype", func(o *Obfuscation) { o.H4 = 3 }, "H4"},
		{"h-collision-1-2", func(o *Obfuscation) { o.H1 = 0xDEADBEEF; o.H2 = 0xDEADBEEF }, "H1 and H2"},
		{"h-collision-3-4", func(o *Obfuscation) { o.H3 = 0xCAFEBABE; o.H4 = 0xCAFEBABE }, "H3 and H4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.mut(&o)
			err := o.Validate()
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestGenerateObfuscationDeterministic(t *testing.T) {
	a, err := GenerateObfuscationFromReader(seededReader(0xCAFE))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := GenerateObfuscationFromReader(seededReader(0xCAFE))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %+v vs %+v", a, b)
	}
}

func TestGenerateObfuscationProducesValidValues(t *testing.T) {
	o, err := GenerateObfuscationFromReader(seededReader(0xBEEF))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("generated obfuscation must validate: %v\n%+v", err, o)
	}
	// Sanity: in the recommended sub-ranges from generateObfuscation.
	if o.Jc < 4 || o.Jc > 10 {
		t.Errorf("Jc %d outside recommended [4,10]", o.Jc)
	}
	if o.Jmin < 50 || o.Jmin > 100 {
		t.Errorf("Jmin %d outside recommended [50,100]", o.Jmin)
	}
	if o.Jmax < o.Jmin+50 || o.Jmax > 1000 {
		t.Errorf("Jmax %d outside recommended [Jmin+50,1000]", o.Jmax)
	}
	if o.S1 < 15 || o.S1 > 150 {
		t.Errorf("S1 %d outside recommended [15,150]", o.S1)
	}
	if o.S2 < 15 || o.S2 > 150 {
		t.Errorf("S2 %d outside recommended [15,150]", o.S2)
	}
}

func TestGenerateObfuscationProduction(t *testing.T) {
	o, err := GenerateObfuscation()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("production obfuscation must validate: %v\n%+v", err, o)
	}
}
