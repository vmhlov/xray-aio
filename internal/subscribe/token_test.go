package subscribe

import (
	"crypto/rand"
	"strings"
	"testing"
)

func mustSecret(t *testing.T) []byte {
	t.Helper()
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != SecretBytes {
		t.Fatalf("secret length: %d", len(s))
	}
	return s
}

func TestGenerateSecretIsUnique(t *testing.T) {
	a := mustSecret(t)
	b := mustSecret(t)
	if string(a) == string(b) {
		t.Fatal("two GenerateSecret calls returned identical bytes")
	}
}

func TestMakeAndVerifyRoundtrip(t *testing.T) {
	secret := mustSecret(t)
	for _, id := range []string{
		"default",
		"alice@example.com",
		"f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"id with spaces and . dots",
		"id/with/slashes",
	} {
		t.Run(id, func(t *testing.T) {
			tok, err := MakeToken(secret, id)
			if err != nil {
				t.Fatalf("MakeToken: %v", err)
			}
			if strings.ContainsAny(tok, " /") {
				t.Errorf("token must be URL-safe: %q", tok)
			}
			got, err := VerifyToken(secret, tok)
			if err != nil {
				t.Fatalf("VerifyToken: %v", err)
			}
			if got != id {
				t.Errorf("roundtrip mismatch: got %q want %q", got, id)
			}
		})
	}
}

func TestVerifyTokenRejectsTampering(t *testing.T) {
	secret := mustSecret(t)
	tok, err := MakeToken(secret, "default")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(tok, ".", 2)
	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dot", "noseparator"},
		{"flipped tag", parts[0] + "." + flipFirstChar(parts[1])},
		{"swapped id", "ZGlmZmVyZW50." + parts[1]},
		{"trailing junk", tok + "x"},
		{"non-base64 id", "###." + parts[1]},
		{"non-base64 tag", parts[0] + ".###"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyToken(secret, tc.token); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestVerifyTokenRejectsWrongSecret(t *testing.T) {
	a := mustSecret(t)
	b := mustSecret(t)
	tok, err := MakeToken(a, "default")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(b, tok); err == nil {
		t.Fatal("token from secret A verified under secret B")
	}
}

func TestMakeTokenRejectsBadInputs(t *testing.T) {
	if _, err := MakeToken(nil, "x"); err == nil {
		t.Error("nil secret should error")
	}
	short := make([]byte, 4)
	_, _ = rand.Read(short)
	if _, err := MakeToken(short, "x"); err == nil {
		t.Error("4-byte secret should error")
	}
	if _, err := MakeToken(mustSecret(t), ""); err == nil {
		t.Error("empty id should error")
	}
}

// flipFirstChar perturbs the first base64 character so the decoded
// HMAC tag certainly differs in the first byte. We can't use the last
// char: a 16-byte payload encodes to 22 RawURL-base64 chars whose
// final char carries only 2 meaningful bits, so multiple alphabet
// substitutions decode to the same byte sequence.
func flipFirstChar(s string) string {
	if s == "" {
		return s
	}
	first := s[0]
	repl := byte('A')
	if first == repl {
		repl = 'B'
	}
	return string(repl) + s[1:]
}
