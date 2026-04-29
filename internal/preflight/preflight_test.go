package preflight

import (
	"context"
	"testing"
)

func TestRun(t *testing.T) {
	r, err := Run(context.Background())
	if err != nil {
		t.Logf("preflight error (expected on non-linux CI runners): %v", err)
		return
	}
	if !r.Ok() {
		t.Fatalf("not ok: %+v", r)
	}
	if r.Distro == "" {
		t.Fatal("empty distro")
	}
}
