package hysteria2

import "testing"

func TestGenerateAuthPasswordIsRandomAndStable(t *testing.T) {
	a, err := GenerateAuthPassword()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateAuthPassword()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two consecutive calls returned the same value: %q", a)
	}
	// 32 bytes raw-url base64 ≈ 43 chars (no padding).
	if got := len(a); got < 40 || got > 50 {
		t.Errorf("password length %d out of expected range 40..50: %q", got, a)
	}
}
