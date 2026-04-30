package sysuser

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// fakeRunner records every invocation and returns per-command
// responses keyed by "name args...". An entry without a matching key
// returns (nil, nil), which encodes "command succeeded".
type fakeRunner struct {
	calls [][]string
	out   map[string][]byte
	errs  map[string]error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	key := join(call)
	return f.out[key], f.errs[key]
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}

func TestEnsureCreatesUserAndGroupWhenBothMissing(t *testing.T) {
	notFound := errors.New("nss: not found")
	r := &fakeRunner{
		errs: map[string]error{
			"getent passwd caddy": notFound,
			"getent group caddy":  notFound,
		},
	}
	if err := Ensure(context.Background(), r, "caddy"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	want := [][]string{
		{"getent", "passwd", "caddy"},
		{"getent", "group", "caddy"},
		{"groupadd", "--system", "caddy"},
		{"useradd",
			"--system",
			"--no-create-home",
			"--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin",
			"--gid", "caddy",
			"caddy",
		},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls=%v\nwant=%v", r.calls, want)
	}
}

func TestEnsureSkipsWhenUserAlreadyExists(t *testing.T) {
	r := &fakeRunner{} // every Run() returns (nil, nil) → user exists
	if err := Ensure(context.Background(), r, "xray"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("expected 1 call (just getent passwd), got %v", r.calls)
	}
	want := []string{"getent", "passwd", "xray"}
	if !reflect.DeepEqual(r.calls[0], want) {
		t.Fatalf("calls[0]=%v want %v", r.calls[0], want)
	}
}

func TestEnsureReusesExistingGroup(t *testing.T) {
	notFound := errors.New("not found")
	r := &fakeRunner{
		errs: map[string]error{
			"getent passwd xray": notFound,
			// getent group xray succeeds → group already on the host
		},
	}
	if err := Ensure(context.Background(), r, "xray"); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, c := range r.calls {
		if c[0] == "groupadd" {
			t.Fatalf("groupadd called even though group exists: %v", r.calls)
		}
	}
	// useradd must still happen because the user itself was missing.
	sawUseradd := false
	for _, c := range r.calls {
		if c[0] == "useradd" {
			sawUseradd = true
			break
		}
	}
	if !sawUseradd {
		t.Fatalf("useradd missing from calls: %v", r.calls)
	}
}

func TestEnsureRejectsEmptyName(t *testing.T) {
	r := &fakeRunner{}
	if err := Ensure(context.Background(), r, ""); err == nil {
		t.Fatalf("expected error for empty name")
	}
	if len(r.calls) != 0 {
		t.Fatalf("expected zero runner calls, got %v", r.calls)
	}
}

func TestEnsurePropagatesGroupaddError(t *testing.T) {
	notFound := errors.New("not found")
	boom := errors.New("groupadd: read-only system")
	r := &fakeRunner{
		errs: map[string]error{
			"getent passwd caddy":     notFound,
			"getent group caddy":      notFound,
			"groupadd --system caddy": boom,
		},
	}
	err := Ensure(context.Background(), r, "caddy")
	if err == nil {
		t.Fatalf("expected error from groupadd")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error chain missing groupadd cause: %v", err)
	}
}

func TestEnsurePropagatesUseraddError(t *testing.T) {
	notFound := errors.New("not found")
	boom := errors.New("useradd: cannot create user")
	r := &fakeRunner{
		errs: map[string]error{
			"getent passwd xray": notFound,
			"getent group xray":  notFound,
			"useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --gid xray xray": boom,
		},
	}
	err := Ensure(context.Background(), r, "xray")
	if err == nil {
		t.Fatalf("expected error from useradd")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("error chain missing useradd cause: %v", err)
	}
}
