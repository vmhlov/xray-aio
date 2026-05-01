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

// TestInstallSkipPreflightHonoursPreflightErrReturn pins the
// regression where Install bailed on the err returned by
// [preflight.Run] before checking SkipPreflightOnError. The real
// preflight.Run returns (Result, errors.New("preflight failed"))
// whenever any check fails — Install must downgrade that to a
// warning when the operator passes --skip-preflight-errors.
func TestInstallSkipPreflightHonoursPreflightErrReturn(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	failingWithErr := func(_ context.Context) (preflight.Result, error) {
		return preflight.Result{
			Checks: []preflight.Check{{Name: "ports", Status: preflight.StatusError, Message: "443 in use"}},
		}, errors.New("preflight failed")
	}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: failingWithErr,
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
		t.Fatalf("expected install to succeed with skip flag even when PreflightFn returned err: %v", err)
	}
	if len(xray.installCalls)+len(naive.installCalls) != 2 {
		t.Errorf("transports must run when skip flag downgrades preflight err; got %d calls", len(xray.installCalls)+len(naive.installCalls))
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

// home-mobile installs three transports (xray, naive, hysteria2) and
// the bundle published under <site>/sub/<token>/ MUST contain a
// hysteria2:// URI alongside the existing vless:// and naive+https://.
func TestInstallHomeMobileWiresHysteria2(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			case "hysteria2":
				return hy2, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile:       "home-mobile",
		Domain:        "example.com",
		NaiveSiteRoot: siteRoot,
	}, deps)
	if err != nil {
		t.Fatalf("Install home-mobile: %v", err)
	}
	if res.State.Hysteria2 == nil {
		t.Fatal("State.Hysteria2 must be populated for home-mobile")
	}
	if res.State.Hysteria2.Password == "" {
		t.Error("Hysteria2.Password empty")
	}
	if res.State.Hysteria2.ListenPort != 443 {
		t.Errorf("Hysteria2.ListenPort default mismatch: %d", res.State.Hysteria2.ListenPort)
	}
	if len(hy2.installCalls) != 1 {
		t.Fatalf("hysteria2 Install called %d times", len(hy2.installCalls))
	}
	hy2Extra := hy2.installCalls[0].Extra
	if hy2Extra["hysteria2.password"].(string) != res.State.Hysteria2.Password {
		t.Errorf("hysteria2.password in Extra mismatch")
	}
	if hy2Extra["hysteria2.listen_port"].(int) != 443 {
		t.Errorf("hysteria2.listen_port in Extra: %v", hy2Extra["hysteria2.listen_port"])
	}
	// Default-style masquerade MUST be domain-based, not loopback —
	// see plan.go's commentary. SNI must match Caddy's strict site
	// definition (`<Domain>:<SelfStealPort>`) or the upstream TLS
	// handshake fails and active probes get a 502 instead of the
	// convincing selfsteal HTML.
	if got, _ := hy2Extra["hysteria2.masquerade_url"].(string); got != "https://example.com:8443" {
		t.Errorf("hysteria2.masquerade_url = %q, want https://example.com:8443 (domain-based default)", got)
	}
	// Conversely, masquerade_insecure must NOT be set: the new
	// domain-based default upstream gets a real cert match, no skip
	// needed.
	if v, ok := hy2Extra["hysteria2.masquerade_insecure"]; ok {
		t.Errorf("hysteria2.masquerade_insecure must be unset for domain-based default; got %v", v)
	}
	plain, err := os.ReadFile(filepath.Join(res.BundleDir, "plain.txt"))
	if err != nil {
		t.Fatalf("read plain: %v", err)
	}
	body := string(plain)
	if !strings.Contains(body, "vless://") {
		t.Errorf("plain.txt missing vless://: %s", body)
	}
	if !strings.Contains(body, "naive+https://") {
		t.Errorf("plain.txt missing naive+https://: %s", body)
	}
	if !strings.Contains(body, "hysteria2://") {
		t.Errorf("plain.txt missing hysteria2://: %s", body)
	}
}

// External operator-pinned masquerade keeps cert verification on
// (the upstream is genuinely public, MITM verification matters
// there). The default home-mobile install in
// TestInstallHomeMobileWiresHysteria2 also leaves it unset because
// the new domain-based default upstream gets a real LE cert match.
// `masquerade_insecure` is reserved for an explicit operator opt-in
// in a future PR.
func TestInstallHomeMobileExternalMasqueradeKeepsTLSVerify(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			case "hysteria2":
				return hy2, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile:                "home-mobile",
		Domain:                 "example.com",
		NaiveSiteRoot:          siteRoot,
		Hysteria2MasqueradeURL: "https://news.ycombinator.com",
	}, deps); err != nil {
		t.Fatalf("Install home-mobile: %v", err)
	}
	hy2Extra := hy2.installCalls[0].Extra
	if v, ok := hy2Extra["hysteria2.masquerade_insecure"]; ok {
		t.Errorf("hysteria2.masquerade_insecure must be unset for external masquerade; got %v", v)
	}
}

// home-stealth must NOT install hysteria2 even if the transport is
// registered; the profile registry alone gates which transports fire.
func TestInstallHomeStealthSkipsHysteria2(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
	deps := Deps{
		Rand:        &deterministicReader{},
		PreflightFn: stubPreflight,
		NewTransport: func(name string) (transport.Transport, error) {
			switch name {
			case "xray":
				return xray, nil
			case "naive":
				return naive, nil
			case "hysteria2":
				return hy2, nil
			}
			return nil, errors.New("unknown")
		},
		StatePath: statePath,
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-stealth", Domain: "example.com", NaiveSiteRoot: siteRoot,
	}, deps)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.State.Hysteria2 != nil {
		t.Errorf("Hysteria2 must be nil for home-stealth, got %+v", res.State.Hysteria2)
	}
	if len(hy2.installCalls) != 0 {
		t.Errorf("hysteria2 Install must not be called for home-stealth, called %d times", len(hy2.installCalls))
	}
}

// On re-install with a new --hysteria2-port, the password is preserved
// (so existing clients keep working) but the port follows the new value.
func TestInstallReinstallHomeMobilePreservesPasswordRotatesPort(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
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
				case "hysteria2":
					return hy2, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	first, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
	}, mkDeps())
	if err != nil {
		t.Fatalf("first install: %v", err)
	}
	second, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
		Hysteria2Port: 12443,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if first.State.Hysteria2.Password != second.State.Hysteria2.Password {
		t.Errorf("Hysteria2.Password rotated on re-install: %q vs %q",
			first.State.Hysteria2.Password, second.State.Hysteria2.Password)
	}
	if second.State.Hysteria2.ListenPort != 12443 {
		t.Errorf("Hysteria2.ListenPort = %d, want 12443", second.State.Hysteria2.ListenPort)
	}
}

// On re-install with a new --naive-selfsteal-port, Hysteria2.MasqueradeURL
// must follow the new port when it's still default-style (domain-based) —
// else hy2's masquerade points to a port nothing listens on, active DPI
// probes get connection-error instead of a convincing site, and the
// proxy is fingerprintable. Mirrors TestInstallReinstallSyncsXrayDestWithSelfStealPort.
func TestInstallReinstallSyncsHysteria2MasqueradeWithSelfStealPort(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
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
				case "hysteria2":
					return hy2, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
	}, mkDeps()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
		NaiveSelfStealPort: 9443,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if got := res.State.Hysteria2.MasqueradeURL; got != "https://example.com:9443" {
		t.Errorf("Hysteria2.MasqueradeURL = %q, want https://example.com:9443 (must follow new SelfStealPort with Domain)", got)
	}
	hy2Extra := hy2.installCalls[len(hy2.installCalls)-1].Extra
	if got, _ := hy2Extra["hysteria2.masquerade_url"].(string); got != "https://example.com:9443" {
		t.Errorf("hysteria2.masquerade_url in Extra = %q, want https://example.com:9443", got)
	}
}

// State files written by xray-aio < #21 hold a loopback masquerade
// URL (https://127.0.0.1:<SelfStealPort>) which now causes a TLS SNI
// mismatch against Caddy and a 502 on probes. On re-install with a
// recognized legacy-loopback URL in state, the orchestrator MUST
// rewrite it to the new domain-based default so the regression is
// healed silently — operators don't have to know about the SNI
// gotcha and don't need to manually edit state.json.
func TestInstallReinstallMigratesLegacyLoopbackMasquerade(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
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
				case "hysteria2":
					return hy2, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	// Simulate state.json from xray-aio < #21: pin loopback URL.
	if _, err := Install(context.Background(), InstallOptions{
		Profile:                "home-mobile",
		Domain:                 "example.com",
		NaiveSiteRoot:          siteRoot,
		Hysteria2MasqueradeURL: "https://127.0.0.1:8443",
	}, mkDeps()); err != nil {
		t.Fatalf("seed install: %v", err)
	}
	// Re-install with no override (default-style migration).
	res, err := Install(context.Background(), InstallOptions{
		Profile:       "home-mobile",
		Domain:        "example.com",
		NaiveSiteRoot: siteRoot,
	}, mkDeps())
	if err != nil {
		t.Fatalf("re-install: %v", err)
	}
	if got := res.State.Hysteria2.MasqueradeURL; got != "https://example.com:8443" {
		t.Errorf("Hysteria2.MasqueradeURL = %q, want https://example.com:8443 (legacy loopback must be migrated)", got)
	}
}

// Conversely, an externally-pinned masquerade (e.g. a public site for
// extra cover) must NOT be clobbered when the operator changes only
// --naive-selfsteal-port. Mirrors TestInstallReinstallPreservesExternalXrayDest.
func TestInstallReinstallPreservesExternalHysteria2Masquerade(t *testing.T) {
	statePath, siteRoot := setupTestState(t)
	xray := &fakeTransport{name: "xray"}
	naive := &fakeTransport{name: "naive"}
	hy2 := &fakeTransport{name: "hysteria2"}
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
				case "hysteria2":
					return hy2, nil
				}
				return nil, errors.New("unknown")
			},
			StatePath: statePath,
		}
	}
	if _, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
		Hysteria2MasqueradeURL: "https://news.ycombinator.com",
	}, mkDeps()); err != nil {
		t.Fatalf("first install: %v", err)
	}
	res, err := Install(context.Background(), InstallOptions{
		Profile: "home-mobile", Domain: "example.com", NaiveSiteRoot: siteRoot,
		NaiveSelfStealPort: 9443,
	}, mkDeps())
	if err != nil {
		t.Fatalf("second install: %v", err)
	}
	if got := res.State.Hysteria2.MasqueradeURL; got != "https://news.ycombinator.com" {
		t.Errorf("Hysteria2.MasqueradeURL = %q, want unchanged https://news.ycombinator.com", got)
	}
}

func TestStatusErrorsWhenNoInstall(t *testing.T) {
	statePath, _ := setupTestState(t)
	deps := Deps{StatePath: statePath, NewTransport: func(string) (transport.Transport, error) { return nil, errors.New("unused") }}
	if _, err := Status(context.Background(), deps); err == nil {
		t.Fatal("expected error when state.json is empty")
	}
}
