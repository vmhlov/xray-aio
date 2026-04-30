package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/state"
	"github.com/vmhlov/xray-aio/internal/transport"
)

// fakeTransport records Install/Status/Probe calls so install_test can
// assert that the orchestrator passed the right Options to each
// transport without needing a real binary on disk.
type fakeTransport struct {
	mu           sync.Mutex
	name         string
	installCalls []transport.Options
	installErr   error
	statusVal    transport.Status
	probeVal     transport.ProbeResult
}

func (f *fakeTransport) Name() string { return f.name }
func (f *fakeTransport) Install(_ context.Context, opts transport.Options) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installCalls = append(f.installCalls, opts)
	return f.installErr
}
func (f *fakeTransport) Start(_ context.Context) error { return nil }
func (f *fakeTransport) Stop(_ context.Context) error  { return nil }
func (f *fakeTransport) Status(_ context.Context) (transport.Status, error) {
	return f.statusVal, nil
}
func (f *fakeTransport) Probe(_ context.Context) (transport.ProbeResult, error) {
	return f.probeVal, nil
}
func (f *fakeTransport) Uninstall(_ context.Context) error { return nil }

// stubPreflight returns a preflight.Result with no errors so Install
// proceeds past the preflight gate in tests.
func stubPreflight(_ context.Context) (preflight.Result, error) {
	return preflight.Result{
		OS:   "linux",
		Arch: "amd64",
		Checks: []preflight.Check{
			{Name: "stub", Status: preflight.StatusOK, Message: "ok"},
		},
	}, nil
}

func setupTestState(t *testing.T) (statePath, siteRoot string) {
	t.Helper()
	tmp := t.TempDir()
	statePath = filepath.Join(tmp, "state.json")
	siteRoot = filepath.Join(tmp, "naive-site")
	t.Cleanup(func() { _ = os.Unsetenv(stateEnvVar) })
	return statePath, siteRoot
}

func TestInstallHappyPath(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		Now:       func() time.Time { return time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC) },
		StatePath: statePath,
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile:       "home-stealth",
		Domain:        "example.com",
		Email:         "ops@example.com",
		NaiveSiteRoot: siteRoot,
	}, deps)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.SubscriptionURL == "" {
		t.Fatal("SubscriptionURL empty")
	}
	if !strings.HasPrefix(res.SubscriptionURL, "https://example.com:8444/sub/") {
		t.Errorf("SubscriptionURL: %q", res.SubscriptionURL)
	}
	if !strings.HasSuffix(res.SubscriptionURL, "/") {
		t.Errorf("SubscriptionURL must end with '/' so file_server resolves index.html: %q", res.SubscriptionURL)
	}
	// Bundle artifacts on disk.
	idx := filepath.Join(res.BundleDir, "index.html")
	plain := filepath.Join(res.BundleDir, "plain.txt")
	for _, p := range []string{idx, plain} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s on disk: %v", p, err)
		}
	}
	plainBody, err := os.ReadFile(plain)
	if err != nil {
		t.Fatalf("read plain: %v", err)
	}
	if !strings.Contains(string(plainBody), "vless://") || !strings.Contains(string(plainBody), "naive+https://") {
		t.Errorf("plain.txt should contain both vless:// and naive+https:// URIs:\n%s", plainBody)
	}
	// Each transport saw one Install call with the right knobs.
	if len(xray.installCalls) != 1 {
		t.Fatalf("xray Install called %d times", len(xray.installCalls))
	}
	xrayExtra := xray.installCalls[0].Extra
	if xrayExtra["xray.uuid"].(string) != res.State.Xray.UUID {
		t.Errorf("xray.uuid mismatch")
	}
	if xrayExtra["xray.listen_port"].(int) != 443 {
		t.Errorf("xray.listen_port: %v", xrayExtra["xray.listen_port"])
	}
	if len(naive.installCalls) != 1 {
		t.Fatalf("naive Install called %d times", len(naive.installCalls))
	}
	naiveExtra := naive.installCalls[0].Extra
	if naiveExtra["naive.username"].(string) != res.State.Naive.Username {
		t.Errorf("naive.username mismatch")
	}
	// State.json on disk has the orchestrator slice.
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("state.json missing: %v", err)
	}
	loaded, err := state.Load()
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	ps, err := loadProfileState(loaded)
	if err != nil || ps == nil {
		t.Fatalf("profile state missing: %v", err)
	}
	if ps.Xray.UUID != res.State.Xray.UUID {
		t.Errorf("persisted UUID drift: %q vs %q", ps.Xray.UUID, res.State.Xray.UUID)
	}
}

func TestInstallSecondRunReusesState(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	mkDeps := func() Deps {
		return Deps{
			Rand:        &deterministicReader{},
			PreflightFn: stubPreflight,
			NewTransport: func(name string) (transport.Transport, error) {
				switch name {
				case "xray":
					return xray, nil
				case "naive":
					return naive, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	opts := InstallOptions{Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot}

	first, err := Install(context.Background(), opts, mkDeps())
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	second, err := Install(context.Background(), opts, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	// Identical UUID/keys/secret across runs.
	if first.State.Xray.UUID != second.State.Xray.UUID {
		t.Errorf("UUID rotated on re-install: %q vs %q", first.State.Xray.UUID, second.State.Xray.UUID)
	}
	if first.State.Subscription.Token != second.State.Subscription.Token {
		t.Errorf("Token rotated on re-install: %q vs %q", first.State.Subscription.Token, second.State.Subscription.Token)
	}
}

func TestInstallRejectsCrossProfile(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	if _, err := Install(context.Background(), InstallOptions{Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot}, deps); err != nil {
		t.Fatalf("first install: %v", err)
	}
	// Inject a fake "other" profile by mutating the registry.
	profiles["other"] = Profile{Name: "other", Transports: []string{"xray"}}
	t.Cleanup(func() { delete(profiles, "other") })
	if _, err := Install(context.Background(), InstallOptions{Profile: "other", Domain: "example.com", NaiveSiteRoot: siteRoot}, deps); err == nil {
		t.Fatal("expected cross-profile install to be rejected")
	}
}

func TestInstallStopsOnPreflightError(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	failing := func(_ context.Context) (preflight.Result, error) {
		return preflight.Result{
			Checks: []preflight.Check{
				{Name: "ports", Status: preflight.StatusError, Message: "443 in use"},
			},
		}, nil
	}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: failing,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	_, err := Install(context.Background(), InstallOptions{Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot}, deps)
	if err == nil {
		t.Fatal("expected install to fail on preflight error")
	}
	if len(xray.installCalls)+len(naive.installCalls) != 0 {
		t.Errorf("transports must not be installed when preflight errors")
	}
}

func TestInstallCanSkipPreflightErrors(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	failing := func(_ context.Context) (preflight.Result, error) {
		return preflight.Result{
			Checks: []preflight.Check{{Name: "ports", Status: preflight.StatusError, Message: "443 in use"}},
		}, nil
	}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: failing,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	_, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com",
		NaiveSiteRoot:        siteRoot,
		SkipPreflightOnError: true,
	}, deps)
	if err != nil {
		t.Fatalf("expected install to succeed with skip flag: %v", err)
	}
}

func TestInstallSurfacesTransportError(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray", installErr: errors.New("boom")}
	naive := &fakeTransport{name: "naive"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	_, err := Install(context.Background(), InstallOptions{Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot}, deps)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}
	// Naive must not have been touched once xray failed.
	if len(naive.installCalls) != 0 {
		t.Errorf("naive installed despite xray failure: %d calls", len(naive.installCalls))
	}
}

func TestInstallRejectsEmptyDomain(t *testing.T) {
	t.Parallel()
	_, err := Install(context.Background(), InstallOptions{Profile: "home-stealth"}, Deps{})
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestSubscriptionURLOmitsDefaultPort(t *testing.T) {
	t.Parallel()
	ps := &ProfileState{
		Domain:       "example.com",
		Naive:        &NaiveState{ListenPort: 443},
		Subscription: &SubscriptionState{Token: "tok"},
	}
	got := subscriptionURL(ps)
	want := "https://example.com/sub/tok/"
	if got != want {
		t.Errorf("subscriptionURL: got %q want %q", got, want)
	}
}

func TestStatusReflectsInstall(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{
		name:      "xray",
		statusVal: transport.Status{Running: true, Notes: "active"},
		probeVal:  transport.ProbeResult{OK: true, Latency: 7, Notes: "tcp ok"},
	}
	naive := &fakeTransport{
		name:      "naive",
		statusVal: transport.Status{Running: true, Notes: "active"},
		probeVal:  transport.ProbeResult{OK: false, Notes: "still warming up"},
	}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	if _, err := Install(context.Background(), InstallOptions{Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot}, deps); err != nil {
		t.Fatalf("install: %v", err)
	}
	rep, err := Status(context.Background(), deps)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if rep.Profile != "home-stealth" || rep.Domain != "example.com" {
		t.Errorf("status header drift: %+v", rep)
	}
	if len(rep.Transports) != 2 {
		t.Fatalf("Transports len: %d", len(rep.Transports))
	}
	if !rep.Transports[0].Status.Running || !rep.Transports[0].Probe.OK {
		t.Errorf("xray status: %+v", rep.Transports[0])
	}
	if rep.Transports[1].Probe.OK {
		t.Errorf("naive probe should still be down: %+v", rep.Transports[1])
	}
}

// Regression for the bug where --naive-site-root only steered the
// orchestrator's bundle write path; the Naive Caddyfile kept the
// default SiteRoot and Caddy returned 404 for /sub/<token>/.
func TestInstallPropagatesNaiveSiteRootToTransport(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile:       "home-stealth",
		Domain:        "example.com",
		NaiveSiteRoot: siteRoot,
	}, deps)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(naive.installCalls) != 1 {
		t.Fatalf("naive Install calls: %d", len(naive.installCalls))
	}
	got, _ := naive.installCalls[0].Extra["naive.site_root"].(string)
	if got != siteRoot {
		t.Fatalf("naive.site_root in Extra: %q (want %q)", got, siteRoot)
	}
	// BundleDir must be a child of siteRoot — same directory Caddy
	// will file_serve from.
	if !strings.HasPrefix(res.BundleDir, siteRoot+string(filepath.Separator)) {
		t.Fatalf("BundleDir %q is not under siteRoot %q", res.BundleDir, siteRoot)
	}
}

// On re-install the operator may pass a NEW --naive-site-root; the
// orchestrator must update both the rendered Caddyfile AND the bundle
// write path so they stay aligned.
func TestInstallReinstallRefreshesNaiveSiteRoot(t *testing.T) {
	statePath, firstRoot := setupTestState(t)
	tmp := t.TempDir()
	secondRoot := filepath.Join(tmp, "naive-site-second")
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	mkDeps := func() Deps {
		return Deps{
			Rand:        &deterministicReader{},
			PreflightFn: stubPreflight,
			NewTransport: func(name string) (transport.Transport, error) {
				switch name {
				case "xray":
					return xray, nil
				case "naive":
					return naive, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: firstRoot,
	}, mkDeps()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: secondRoot,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	got, _ := naive.installCalls[len(naive.installCalls)-1].Extra["naive.site_root"].(string)
	if got != secondRoot {
		t.Errorf("re-install: naive.site_root in Extra %q (want %q)", got, secondRoot)
	}
	if !strings.HasPrefix(res.BundleDir, secondRoot+string(filepath.Separator)) {
		t.Errorf("re-install BundleDir %q is not under %q", res.BundleDir, secondRoot)
	}
}

// On re-install with a new --naive-selfsteal-port, ps.Xray.Dest must
// follow the new port when it's still default-style (loopback) — else
// REALITY relays a snooper to the OLD port where Caddy no longer
// listens, silently breaking the stealth chain.
func TestInstallReinstallSyncsXrayDestWithSelfStealPort(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	mkDeps := func() Deps {
		return Deps{
			Rand:        &deterministicReader{},
			PreflightFn: stubPreflight,
			NewTransport: func(name string) (transport.Transport, error) {
				switch name {
				case "xray":
					return xray, nil
				case "naive":
					return naive, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot,
	}, mkDeps()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot,
		NaiveSelfStealPort: 9443,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if got := res.State.Xray.Dest; got != "127.0.0.1:9443" {
		t.Errorf("Xray.Dest = %q, want 127.0.0.1:9443 (must follow new SelfStealPort)", got)
	}
	if got, _ := naive.installCalls[len(naive.installCalls)-1].Extra["naive.selfsteal_port"].(int); got != 9443 {
		t.Errorf("naive.selfsteal_port in Extra = %d, want 9443", got)
	}
	if got, _ := xray.installCalls[len(xray.installCalls)-1].Extra["xray.dest"].(string); got != "127.0.0.1:9443" {
		t.Errorf("xray.dest in Extra = %q, want 127.0.0.1:9443", got)
	}
}

// Conversely, an explicitly-pinned external dest (e.g. CDN) must NOT
// be clobbered when the operator changes only --naive-selfsteal-port.
func TestInstallReinstallPreservesExternalXrayDest(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	mkDeps := func() Deps {
		return Deps{
			Rand:        &deterministicReader{},
			PreflightFn: stubPreflight,
			NewTransport: func(name string) (transport.Transport, error) {
				switch name {
				case "xray":
					return xray, nil
				case "naive":
					return naive, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot,
		XrayDest: "www.cdn.example:443",
	}, mkDeps()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot,
		NaiveSelfStealPort: 9443,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if got := res.State.Xray.Dest; got != "www.cdn.example:443" {
		t.Errorf("Xray.Dest = %q, want unchanged www.cdn.example:443", got)
	}
}

func TestStatusErrorsWhenNoInstall(t *testing.T) {
	statePath, _ := setupTestState(t)
	deps := Deps{StatePath: statePath, NewTransport: func(string) (transport.Transport, error) { return nil, errors.New("unused") }}
	if _, err := Status(context.Background(), deps); err == nil {
		t.Fatal("expected error when state.json is empty")
	}
}
