package mtproto

import (
	"encoding/hex"
	"testing"
)

func TestGenerateSecretShape(t *testing.T) {
	got, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("want 32 hex chars, got %d: %q", len(got), got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
	// validateSecret is the gate we care about — feed it back.
	if err := validateSecret(got); err != nil {
		t.Fatalf("validateSecret round-trip: %v", err)
	}
}

func TestGenerateSecretRandomness(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == b {
		t.Fatalf("two generations collided — catastrophic RNG failure? got %q twice", a)
	}
}
