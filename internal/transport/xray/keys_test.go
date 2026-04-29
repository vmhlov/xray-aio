package xray

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateUUIDFormat(t *testing.T) {
	id, err := GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeUUID(id) {
		t.Fatalf("UUID malformed: %q", id)
	}
	// version 4 — high nibble of byte 6 (which is the 15th hex char,
	// because of dashes — char index 14) must be '4'.
	if id[14] != '4' {
		t.Fatalf("not v4: %q (char 14 = %c)", id, id[14])
	}
	// variant 10xx — byte 8 high two bits, hex char index 19
	switch id[19] {
	case '8', '9', 'a', 'b':
	default:
		t.Fatalf("bad variant nibble: %c in %q", id[19], id)
	}
}

func TestGenerateUUIDDeterministic(t *testing.T) {
	r := bytes.NewReader(make([]byte, 16))
	id, err := generateUUID(r)
	if err != nil {
		t.Fatal(err)
	}
	want := "00000000-0000-4000-8000-000000000000"
	if id != want {
		t.Fatalf("got %q want %q", id, want)
	}
}

func TestGenerateUUIDUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		id, err := GenerateUUID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate UUID: %q", id)
		}
		seen[id] = true
	}
}

func TestGenerateX25519(t *testing.T) {
	keys, err := GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	if keys.Private == "" || keys.Public == "" {
		t.Fatalf("empty keys: %+v", keys)
	}
	if keys.Private == keys.Public {
		t.Fatal("priv == pub")
	}
	enc := base64.RawURLEncoding
	priv, err := enc.DecodeString(keys.Private)
	if err != nil {
		t.Fatalf("private key not RawURL b64: %v", err)
	}
	pub, err := enc.DecodeString(keys.Public)
	if err != nil {
		t.Fatalf("public key not RawURL b64: %v", err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("wrong key length: priv=%d pub=%d", len(priv), len(pub))
	}
}

func TestGenerateShortID(t *testing.T) {
	for _, n := range []int{1, 4, 8, 16} {
		s, err := GenerateShortID(n)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if len(s) != n*2 {
			t.Fatalf("n=%d: got %q (len %d) want len %d", n, s, len(s), n*2)
		}
		if err := validateShortID(s); err != nil {
			t.Fatalf("n=%d: validate: %v", n, err)
		}
	}
}

func TestGenerateShortIDOutOfRange(t *testing.T) {
	for _, n := range []int{0, -1, 17, 100} {
		if _, err := GenerateShortID(n); err == nil {
			t.Fatalf("n=%d: expected error", n)
		}
	}
}

func TestValidateShortID(t *testing.T) {
	good := []string{"a", "ab", "abcd", "deadbeef", "0123456789abcdef"}
	for _, s := range good {
		if err := validateShortID(s); err != nil && len(s)%2 == 0 {
			t.Errorf("validateShortID(%q): unexpected err %v", s, err)
		}
	}
	bad := []string{"", "abc", "ZZ", "deadBEEF", "deadbeefdeadbeefdeadbeef0000000000"}
	for _, s := range bad {
		if err := validateShortID(s); err == nil {
			t.Errorf("validateShortID(%q): expected error", s)
		}
	}
}

func TestLooksLikeUUID(t *testing.T) {
	cases := map[string]bool{
		"00000000-0000-4000-8000-000000000000": true,
		"deadbeef-1234-4567-89ab-0123456789ab": true,
		"DEADBEEF-1234-4567-89AB-0123456789AB": false, // uppercase rejected
		"00000000_0000_4000_8000_000000000000": false, // wrong sep
		"":                                     false,
		"too-short":                            false,
	}
	for in, want := range cases {
		if got := looksLikeUUID(in); got != want {
			t.Errorf("looksLikeUUID(%q)=%v want %v", in, got, want)
		}
	}
}
