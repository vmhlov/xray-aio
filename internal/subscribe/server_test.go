package subscribe

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubResolver struct {
	bundle Bundle
	err    error
	called string
}

func (s *stubResolver) Resolve(id string) (Bundle, error) {
	s.called = id
	return s.bundle, s.err
}

func TestHandlerHTML(t *testing.T) {
	secret, _ := GenerateSecret()
	tok, _ := MakeToken(secret, "alice")
	r := &stubResolver{bundle: Bundle{
		Label:     "alice",
		VLESSURIs: []string{"vless://x@example.com:443"},
	}}
	srv := httptest.NewServer(Handler(secret, r))
	defer srv.Close()

	resp, err := http.Get(srv.URL + PathPrefix + tok)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type: %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control: %q", cc)
	}
	if r.called != "alice" {
		t.Errorf("resolver got %q want alice", r.called)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "vless://x@example.com:443") {
		t.Fatalf("body missing URI:\n%s", body)
	}
}

func TestHandlerPlain(t *testing.T) {
	secret, _ := GenerateSecret()
	tok, _ := MakeToken(secret, "alice")
	r := &stubResolver{bundle: Bundle{
		VLESSURIs: []string{"vless://x@example.com:443"},
	}}
	srv := httptest.NewServer(Handler(secret, r))
	defer srv.Close()

	resp, err := http.Get(srv.URL + PathPrefix + tok + "?plain=1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type: %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "vless://x@example.com:443\n" {
		t.Fatalf("body: %q", body)
	}
}

func TestHandlerBadTokenIs404(t *testing.T) {
	secret, _ := GenerateSecret()
	srv := httptest.NewServer(Handler(secret, &stubResolver{}))
	defer srv.Close()

	for _, path := range []string{
		PathPrefix,                    // empty token
		PathPrefix + "garbage",        // structural fail
		PathPrefix + "alice.deadbeef", // bad tag
		PathPrefix + "alice/bob",      // path traversal attempt
		"/sub//double/slash",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s: status %d (want 404)", path, resp.StatusCode)
		}
	}
}

func TestHandlerNotFoundResolverIs404(t *testing.T) {
	secret, _ := GenerateSecret()
	tok, _ := MakeToken(secret, "missing")
	srv := httptest.NewServer(Handler(secret, &stubResolver{err: ErrNotFound}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + PathPrefix + tok)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestHandlerResolverErrorIs500(t *testing.T) {
	secret, _ := GenerateSecret()
	tok, _ := MakeToken(secret, "alice")
	srv := httptest.NewServer(Handler(secret, &stubResolver{err: errors.New("disk on fire")}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + PathPrefix + tok)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestHandlerRejectsNonGET(t *testing.T) {
	secret, _ := GenerateSecret()
	tok, _ := MakeToken(secret, "alice")
	srv := httptest.NewServer(Handler(secret, &stubResolver{bundle: Bundle{VLESSURIs: []string{"vless://x"}}}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+PathPrefix+tok, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status: %d", resp.StatusCode)
	}
}

func TestHandlerPanicsOnNilSecretOrResolver(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	Handler(nil, nil)
}

// TestHandlerPanicsOnShortSecret pins the constructor's lower bound
// to VerifyToken's. Caught by Devin Review on PR #7: a 1–15 byte
// secret would pass an len==0 check but make every subsequent
// VerifyToken silently fail, returning 404 for all valid tokens
// without an operator-visible signal.
func TestHandlerPanicsOnShortSecret(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on undersized secret")
		}
	}()
	short := make([]byte, SecretBytes/2-1)
	Handler(short, MapResolver{})
}

func TestMapResolver(t *testing.T) {
	r := MapResolver{"alice": Bundle{VLESSURIs: []string{"x"}}}
	got, err := r.Resolve("alice")
	if err != nil || len(got.VLESSURIs) != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := r.Resolve("bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob: %v", err)
	}
}
