package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vmhlov/xray-aio/internal/log"
	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/state"
	"github.com/vmhlov/xray-aio/internal/subscribe"
	"github.com/vmhlov/xray-aio/internal/transport"
	naivetransport "github.com/vmhlov/xray-aio/internal/transport/naive"
)

// InstallOptions is the user-facing flag bag handed to Install. Zero
// values get sensible defaults; only Profile and Domain are required.
type InstallOptions struct {
	// Profile is the name of one of the profiles registered in
	// [profiles] (e.g. "home-stealth").
	Profile string

	// Domain is the FQDN clients use to reach this host. Required.
	Domain string

	// Email is the ACME contact address. Optional but strongly
	// recommended — ACME-anonymous registration is a soft signal.
	Email string

	// XrayPort overrides the default Xray REALITY listen port (443).
	XrayPort int

	// NaivePort overrides the default Naive listen port (8444).
	NaivePort int

	// XrayDest overrides the REALITY upstream destination
	// (default: 127.0.0.1:8443). Phase 1.6 does not auto-install a
	// listener at this address — operator is responsible until
	// Phase 1.7 ships the unified selfsteal Caddy.
	XrayDest string

	// NaiveSiteRoot overrides the directory Naive Caddy file_serves
	// from. The orchestrator writes /sub/<token>/index.html under
	// this path; if empty, [naive.DefaultSiteRoot] is used.
	NaiveSiteRoot string

	// SkipPreflightOnError, when true, downgrades preflight errors
	// to warnings so install proceeds. Reserved for the operator
	// who knows what they're doing — not exposed via CLI yet.
	SkipPreflightOnError bool
}

// InstallResult summarises what Install did. Returned even on failure
// where partial work happened, so callers can clean up.
type InstallResult struct {
	State           *ProfileState
	Bundle          subscribe.Bundle
	SubscriptionURL string
	BundleDir       string
	Preflight       preflight.Result
}

// Deps is the bag of test seams Install consumes. Production callers
// pass the zero value (DefaultDeps applied internally).
type Deps struct {
	// Rand is the randomness source used for fresh secrets. Default:
	// crypto/rand.
	Rand io.Reader

	// PreflightFn drives the preflight stage. Default:
	// preflight.Run.
	PreflightFn func(ctx context.Context) (preflight.Result, error)

	// NewTransport resolves a transport by registry name. Default:
	// transport.Get. Tests pass a recording fake.
	NewTransport func(name string) (transport.Transport, error)

	// Now returns the current time. Default: time.Now.
	Now func() time.Time

	// StatePath overrides the state.json location. When set, takes
	// precedence over the XRAY_AIO_STATE env var. Tests use it to
	// route writes into t.TempDir().
	StatePath string
}

// Install runs the full per-profile install workflow.
func Install(ctx context.Context, opts InstallOptions, deps Deps) (*InstallResult, error) {
	if opts.Domain == "" {
		return nil, errors.New("Domain is required")
	}
	if opts.Profile == "" {
		opts.Profile = ProfileHomeStealth.Name
	}
	profile, err := ResolveProfile(opts.Profile)
	if err != nil {
		return nil, err
	}
	deps = applyDefaults(deps)

	// Phase 1: preflight.
	report, err := deps.PreflightFn(ctx)
	if err != nil {
		return nil, fmt.Errorf("preflight: %w", err)
	}
	if report.HasErrors() && !opts.SkipPreflightOnError {
		return &InstallResult{Preflight: report},
			fmt.Errorf("preflight failed: %d errors, %d warnings",
				countStatus(report, preflight.StatusError),
				countStatus(report, preflight.StatusWarn))
	}

	// Phase 2: load existing state or generate a fresh plan.
	if deps.StatePath != "" {
		if err := os.Setenv(stateEnvVar, deps.StatePath); err != nil {
			return nil, fmt.Errorf("set state path: %w", err)
		}
	}
	s, err := state.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	ps, err := loadProfileState(s)
	if err != nil {
		return nil, err
	}
	if ps == nil {
		ps, err = generatePlan(opts, deps.Rand)
		if err != nil {
			return nil, fmt.Errorf("generate plan: %w", err)
		}
	} else {
		// Re-running install with the same profile: keep secrets,
		// refresh ergonomic fields the operator may have changed.
		if ps.Profile != opts.Profile {
			return nil, fmt.Errorf("state holds profile %q; install requested %q (rotate or uninstall first)", ps.Profile, opts.Profile)
		}
		ps.Domain = opts.Domain
		ps.Email = opts.Email
	}

	// Phase 3: install each transport in profile order.
	for _, name := range profile.Transports {
		t, err := deps.NewTransport(name)
		if err != nil {
			return &InstallResult{State: ps, Preflight: report}, fmt.Errorf("resolve transport %q: %w", name, err)
		}
		topts, err := buildTransportOptions(name, ps)
		if err != nil {
			return &InstallResult{State: ps, Preflight: report}, fmt.Errorf("build options for %q: %w", name, err)
		}
		log.L().Info("install transport", "name", name, "domain", opts.Domain)
		if err := t.Install(ctx, topts); err != nil {
			return &InstallResult{State: ps, Preflight: report}, fmt.Errorf("install %q: %w", name, err)
		}
	}

	// Phase 4: render subscription bundle.
	bundle, err := buildBundle(ps, deps.Now())
	if err != nil {
		return &InstallResult{State: ps, Preflight: report}, fmt.Errorf("build bundle: %w", err)
	}
	siteRoot := opts.NaiveSiteRoot
	if siteRoot == "" {
		siteRoot = naivetransport.DefaultSiteRoot
	}
	bundleDir, err := writeBundle(siteRoot, ps.Subscription.Token, bundle)
	if err != nil {
		return &InstallResult{State: ps, Bundle: bundle, Preflight: report}, fmt.Errorf("write bundle: %w", err)
	}

	// Phase 5: persist state.
	if err := saveProfileState(s, ps); err != nil {
		return &InstallResult{State: ps, Bundle: bundle, BundleDir: bundleDir, Preflight: report},
			fmt.Errorf("save state: %w", err)
	}
	if err := state.Save(s); err != nil {
		return &InstallResult{State: ps, Bundle: bundle, BundleDir: bundleDir, Preflight: report},
			fmt.Errorf("persist state: %w", err)
	}

	return &InstallResult{
		State:           ps,
		Bundle:          bundle,
		BundleDir:       bundleDir,
		SubscriptionURL: subscriptionURL(ps),
		Preflight:       report,
	}, nil
}

// stateEnvVar is the env var [state.Path] consults. Duplicated here so
// Deps.StatePath has a single shared source of truth.
const stateEnvVar = "XRAY_AIO_STATE"

// buildTransportOptions translates the orchestrator's ProfileState
// into the per-transport Options.Extra map each transport package
// expects.
func buildTransportOptions(name string, ps *ProfileState) (transport.Options, error) {
	switch name {
	case "xray":
		if ps.Xray == nil {
			return transport.Options{}, errors.New("xray state missing")
		}
		shortIDs := make([]any, 0, len(ps.Xray.ShortIDs))
		for _, id := range ps.Xray.ShortIDs {
			shortIDs = append(shortIDs, id)
		}
		return transport.Options{
			Domain: ps.Domain,
			Email:  ps.Email,
			Extra: map[string]any{
				"xray.uuid":        ps.Xray.UUID,
				"xray.private_key": ps.Xray.PrivateKey,
				"xray.public_key":  ps.Xray.PublicKey,
				"xray.short_ids":   shortIDs,
				"xray.listen_port": ps.Xray.ListenPort,
				"xray.dest":        ps.Xray.Dest,
				"xray.mode":        ps.Xray.Mode,
			},
		}, nil
	case "naive":
		if ps.Naive == nil {
			return transport.Options{}, errors.New("naive state missing")
		}
		return transport.Options{
			Domain: ps.Domain,
			Email:  ps.Email,
			Extra: map[string]any{
				"naive.username":    ps.Naive.Username,
				"naive.password":    ps.Naive.Password,
				"naive.listen_port": ps.Naive.ListenPort,
			},
		}, nil
	default:
		return transport.Options{}, fmt.Errorf("orchestrator does not know how to configure %q", name)
	}
}

// buildBundle renders the per-client URI bundle from ps. Phase 1.6
// produces one VLESS URI (Vision mode) and one Naive URI.
func buildBundle(ps *ProfileState, now time.Time) (subscribe.Bundle, error) {
	if ps.Xray == nil || ps.Naive == nil {
		return subscribe.Bundle{}, errors.New("Xray/Naive state required for bundle")
	}
	if len(ps.Xray.ShortIDs) == 0 {
		return subscribe.Bundle{}, errors.New("no short ids")
	}
	vless, err := subscribe.VLESSURI(subscribe.VLESSConfig{
		UUID:      ps.Xray.UUID,
		Domain:    ps.Domain,
		Port:      ps.Xray.ListenPort,
		PublicKey: ps.Xray.PublicKey,
		ShortID:   ps.Xray.ShortIDs[0],
		Mode:      ps.Xray.Mode,
		Label:     ps.Domain + " (REALITY)",
	})
	if err != nil {
		return subscribe.Bundle{}, fmt.Errorf("vless uri: %w", err)
	}
	naive, err := subscribe.NaiveURI(subscribe.NaiveConfig{
		Username: ps.Naive.Username,
		Password: ps.Naive.Password,
		Domain:   ps.Domain,
		Port:     ps.Naive.ListenPort,
		Label:    ps.Domain + " (Naive)",
	})
	if err != nil {
		return subscribe.Bundle{}, fmt.Errorf("naive uri: %w", err)
	}
	return subscribe.Bundle{
		Label:       "xray-aio: " + ps.Domain,
		VLESSURIs:   []string{vless},
		NaiveURIs:   []string{naive},
		GeneratedAt: now.UTC().Format(time.RFC3339),
	}, nil
}

// writeBundle materialises bundle as static files under
// <siteRoot>/sub/<token>/. Returns the bundle directory.
func writeBundle(siteRoot, token string, bundle subscribe.Bundle) (string, error) {
	if siteRoot == "" {
		return "", errors.New("siteRoot is empty")
	}
	if token == "" {
		return "", errors.New("token is empty")
	}
	dir := filepath.Join(siteRoot, "sub", token)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	html, err := subscribe.RenderHTML(bundle)
	if err != nil {
		return dir, fmt.Errorf("render html: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0o644); err != nil {
		return dir, fmt.Errorf("write index.html: %w", err)
	}
	plain, err := subscribe.RenderPlainText(bundle)
	if err != nil {
		return dir, fmt.Errorf("render plain: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte(plain), 0o644); err != nil {
		return dir, fmt.Errorf("write plain.txt: %w", err)
	}
	return dir, nil
}

// subscriptionURL builds the externally visible URL where the bundle
// is published. Naive Caddy serves /sub/<token>/index.html directly
// from its file_server.
func subscriptionURL(ps *ProfileState) string {
	if ps == nil || ps.Subscription == nil || ps.Naive == nil {
		return ""
	}
	host := ps.Domain
	if ps.Naive.ListenPort != 443 {
		host = host + ":" + strconv.Itoa(ps.Naive.ListenPort)
	}
	return "https://" + host + "/sub/" + ps.Subscription.Token + "/"
}

// applyDefaults fills in the production defaults for any unset Deps
// field.
func applyDefaults(d Deps) Deps {
	if d.Rand == nil {
		d.Rand = defaultRand
	}
	if d.PreflightFn == nil {
		d.PreflightFn = preflight.Run
	}
	if d.NewTransport == nil {
		d.NewTransport = transport.Get
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return d
}

// countStatus is a small helper duplicated from the cmd package to
// avoid a circular import.
func countStatus(r preflight.Result, target preflight.Status) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == target {
			n++
		}
	}
	return n
}
