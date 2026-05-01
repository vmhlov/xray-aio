package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vmhlov/xray-aio/internal/log"
	"github.com/vmhlov/xray-aio/internal/preflight"
	"github.com/vmhlov/xray-aio/internal/state"
	"github.com/vmhlov/xray-aio/internal/subscribe"
	"github.com/vmhlov/xray-aio/internal/transport"
	amneziawgtransport "github.com/vmhlov/xray-aio/internal/transport/amneziawg"
	hysteria2transport "github.com/vmhlov/xray-aio/internal/transport/hysteria2"
	naivetransport "github.com/vmhlov/xray-aio/internal/transport/naive"
	"rsc.io/qr"
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
	// (default: 127.0.0.1:<NaiveSelfStealPort>). Phase 1.7's unified
	// Caddy serves a static selfsteal site on that port out of the
	// box, so the default lands on a real LE-cert backed listener
	// without operator action.
	XrayDest string

	// NaiveSiteRoot overrides the directory Naive Caddy file_serves
	// from on its public port. The orchestrator writes
	// /sub/<token>/index.html under this path; if empty,
	// [naive.DefaultSiteRoot] is used.
	NaiveSiteRoot string

	// NaiveSelfStealPort overrides the loopback port the unified
	// Caddy uses to serve the REALITY-upstream selfsteal site. Default:
	// [naive.DefaultSelfStealPort] (8443).
	NaiveSelfStealPort int

	// NaiveSelfStealRoot overrides the directory file_served on
	// :NaiveSelfStealPort. MUST differ from NaiveSiteRoot so a
	// REALITY relay never reaches /sub/*. Default:
	// [naive.DefaultSelfStealRoot].
	NaiveSelfStealRoot string

	// Hysteria2Port overrides the UDP port the hysteria 2 transport
	// listens on. Only consulted when the profile contains
	// hysteria2. Default: [hysteria2.DefaultListenPort] (UDP/443).
	Hysteria2Port int

	// Hysteria2MasqueradeURL overrides the URL hysteria 2 proxies to
	// when a probe arrives without valid auth. Only consulted when
	// the profile contains hysteria2. Default:
	// https://<Domain>:<NaiveSelfStealPort> — Caddy's selfsteal site
	// reached via the public hostname so SNI matches Caddy's strict
	// site definition. Linux routes the dial back via loopback
	// automatically.
	Hysteria2MasqueradeURL string

	// AmneziaWGListenPort overrides the AmneziaWG UDP listen port.
	// Only consulted when the profile contains amneziawg. Default:
	// [amneziawg.DefaultListenPort] (51842).
	AmneziaWGListenPort int

	// AmneziaWGServerAddress / AmneziaWGPeerAddress override the
	// in-tunnel CIDR addresses on the server (e.g. "10.66.66.1/24")
	// and peer (e.g. "10.66.66.2/32") sides of the WireGuard link.
	// Defaults: [amneziawg.DefaultServerAddress] /
	// [amneziawg.DefaultPeerAddress].
	AmneziaWGServerAddress string
	AmneziaWGPeerAddress   string

	// AmneziaWGMTU overrides the peer-side MTU value rendered into
	// the .conf. Default: [amneziawg.DefaultMTU] (1380).
	AmneziaWGMTU int

	// AmneziaWGDNS overrides the peer-side DNS server rendered into
	// the .conf. Default: [amneziawg.DefaultDNS] (1.1.1.1).
	AmneziaWGDNS string

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
	deps = applyDefaults(opts, deps)

	// Phase 1: preflight. [preflight.Run] returns a non-nil err
	// whenever any check fails; the caller still gets a populated
	// Result. We only treat the err as fatal when there is no result
	// data (e.g. ctx cancelled) — otherwise SkipPreflightOnError
	// should be able to downgrade preflight failures to warnings.
	report, err := deps.PreflightFn(ctx)
	if err != nil && len(report.Checks) == 0 {
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
		if ps.Naive != nil {
			if opts.NaiveSiteRoot != "" {
				ps.Naive.SiteRoot = opts.NaiveSiteRoot
			}
			if ps.Naive.SiteRoot == "" {
				ps.Naive.SiteRoot = naivetransport.DefaultSiteRoot
			}
			if opts.NaiveSelfStealPort != 0 {
				ps.Naive.SelfStealPort = opts.NaiveSelfStealPort
			}
			if ps.Naive.SelfStealPort == 0 {
				ps.Naive.SelfStealPort = naivetransport.DefaultSelfStealPort
			}
			if opts.NaiveSelfStealRoot != "" {
				ps.Naive.SelfStealRoot = opts.NaiveSelfStealRoot
			}
			if ps.Naive.SelfStealRoot == "" {
				ps.Naive.SelfStealRoot = naivetransport.DefaultSelfStealRoot
			}
		}
		// Keep REALITY's upstream destination in sync with the
		// (possibly just-changed) selfsteal port. Rule:
		//   - operator-supplied --xray-dest always wins;
		//   - otherwise, if state's dest is loopback (default-style),
		//     resync to 127.0.0.1:<SelfStealPort>;
		//   - otherwise (operator pinned dest to a CDN/external host
		//     in a previous install), leave it alone.
		if ps.Xray != nil {
			switch {
			case opts.XrayDest != "":
				ps.Xray.Dest = opts.XrayDest
			case ps.Naive != nil && strings.HasPrefix(ps.Xray.Dest, "127.0.0.1:"):
				ps.Xray.Dest = fmt.Sprintf("127.0.0.1:%d", ps.Naive.SelfStealPort)
			}
		}

		if profileNeedsHysteria2(ps.Profile) {
			if ps.Hysteria2 == nil {
				hyPass, err := generateHysteria2PasswordFrom(deps.Rand)
				if err != nil {
					return nil, fmt.Errorf("hysteria2 password: %w", err)
				}
				ps.Hysteria2 = &Hysteria2State{Password: hyPass}
			}
			if opts.Hysteria2Port != 0 {
				ps.Hysteria2.ListenPort = opts.Hysteria2Port
			}
			if ps.Hysteria2.ListenPort == 0 {
				ps.Hysteria2.ListenPort = hysteria2transport.DefaultListenPort
			}
			// Masquerade URL precedence on re-install mirrors the
			// Xray.Dest sync above:
			//   - explicit --hysteria2-masquerade wins;
			//   - otherwise, if state holds a default-style URL —
			//     either the new domain-based form
			//     (https://<Domain>:*) or the legacy loopback form
			//     (https://127.0.0.1:*, written by xray-aio < #21) —
			//     refresh it to https://<Domain>:<NaiveSelfStealPort>
			//     so probes still land on Caddy's selfsteal site
			//     (and SNI matches Caddy's strict site definition);
			//   - otherwise (operator pinned an external masquerade,
			//     e.g. https://news.ycombinator.com), leave it alone;
			//   - if state is empty (fresh install on existing
			//     state.json without hy2), fall back to default.
			// Defensive: every default-style branch is guarded by
			// `ps.Naive != nil` (handled by the earlier case) — the
			// orchestrator's Phase 1 invariant requires Naive
			// alongside Hysteria2, but a hand-edited state.json
			// could break that, and we should not panic.
			switch {
			case opts.Hysteria2MasqueradeURL != "":
				ps.Hysteria2.MasqueradeURL = opts.Hysteria2MasqueradeURL
			case ps.Naive == nil:
				// No selfsteal target — leave whatever was there;
				// Hysteria2 will still come up but masquerade won't
				// be useful until the operator re-runs install with
				// a profile that carries Naive.
			case strings.HasPrefix(ps.Hysteria2.MasqueradeURL, "https://127.0.0.1:"):
				// Legacy loopback URL written by xray-aio < #21 —
				// migrate to domain-form so SNI matches Caddy.
				ps.Hysteria2.MasqueradeURL = fmt.Sprintf("https://%s:%d", opts.Domain, ps.Naive.SelfStealPort)
			case strings.HasPrefix(ps.Hysteria2.MasqueradeURL, fmt.Sprintf("https://%s:", opts.Domain)):
				// Current domain-form default — refresh to follow
				// the (possibly just-changed) NaiveSelfStealPort.
				ps.Hysteria2.MasqueradeURL = fmt.Sprintf("https://%s:%d", opts.Domain, ps.Naive.SelfStealPort)
			case ps.Hysteria2.MasqueradeURL == "":
				// First-time wiring on existing state.json that
				// didn't have a Hysteria2 block.
				ps.Hysteria2.MasqueradeURL = fmt.Sprintf("https://%s:%d", opts.Domain, ps.Naive.SelfStealPort)
			}
		}

		if profileNeedsAmneziaWG(ps.Profile) {
			// AmneziaWG re-install policy: keys + obfuscation params
			// MUST be preserved across re-runs (the peer's already
			// distributed .conf becomes invalid otherwise). We
			// only refresh the ergonomic knobs (listen port, in-
			// tunnel addresses, MTU, DNS).
			//
			// First-run on an existing state.json that didn't have
			// an AmneziaWG block populates one fresh. The plain
			// generatePlan path also lands here when an operator
			// switches to home-vpn after a fresh-install on
			// home-stealth (rotate-style flow), but that's not
			// supported in v1 — `Install` errors out with the
			// "state holds profile %q" guard above before reaching
			// this branch.
			if ps.AmneziaWG == nil {
				awg, err := generateAmneziaWGStateFrom(opts, deps.Rand)
				if err != nil {
					return nil, fmt.Errorf("amneziawg: %w", err)
				}
				ps.AmneziaWG = awg
			}
			if opts.AmneziaWGListenPort != 0 {
				ps.AmneziaWG.ListenPort = opts.AmneziaWGListenPort
			}
			if ps.AmneziaWG.ListenPort == 0 {
				ps.AmneziaWG.ListenPort = amneziawgtransport.DefaultListenPort
			}
			if opts.AmneziaWGServerAddress != "" {
				ps.AmneziaWG.ServerAddress = opts.AmneziaWGServerAddress
			}
			if ps.AmneziaWG.ServerAddress == "" {
				ps.AmneziaWG.ServerAddress = amneziawgtransport.DefaultServerAddress
			}
			if opts.AmneziaWGPeerAddress != "" {
				ps.AmneziaWG.PeerAddress = opts.AmneziaWGPeerAddress
			}
			if ps.AmneziaWG.PeerAddress == "" {
				ps.AmneziaWG.PeerAddress = amneziawgtransport.DefaultPeerAddress
			}
			if opts.AmneziaWGMTU != 0 {
				ps.AmneziaWG.MTU = opts.AmneziaWGMTU
			}
			if ps.AmneziaWG.MTU == 0 {
				ps.AmneziaWG.MTU = amneziawgtransport.DefaultMTU
			}
			if opts.AmneziaWGDNS != "" {
				ps.AmneziaWG.DNS = opts.AmneziaWGDNS
			}
			if ps.AmneziaWG.DNS == "" {
				ps.AmneziaWG.DNS = amneziawgtransport.DefaultDNS
			}
		}
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
	// Single source of truth for SiteRoot is ps.Naive.SiteRoot. The
	// bundle MUST land under the same directory the naive transport's
	// Caddyfile file_servers from, otherwise /sub/<token>/ 404s.
	siteRoot := ""
	if ps.Naive != nil {
		siteRoot = ps.Naive.SiteRoot
	}
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
		extra := map[string]any{
			"naive.username":    ps.Naive.Username,
			"naive.password":    ps.Naive.Password,
			"naive.listen_port": ps.Naive.ListenPort,
		}
		if ps.Naive.SiteRoot != "" {
			extra["naive.site_root"] = ps.Naive.SiteRoot
		}
		if ps.Naive.SelfStealPort != 0 {
			extra["naive.selfsteal_port"] = ps.Naive.SelfStealPort
		}
		if ps.Naive.SelfStealRoot != "" {
			extra["naive.selfsteal_root"] = ps.Naive.SelfStealRoot
		}
		return transport.Options{
			Domain: ps.Domain,
			Email:  ps.Email,
			Extra:  extra,
		}, nil
	case "hysteria2":
		if ps.Hysteria2 == nil {
			return transport.Options{}, errors.New("hysteria2 state missing")
		}
		extra := map[string]any{
			"hysteria2.password":    ps.Hysteria2.Password,
			"hysteria2.listen_port": ps.Hysteria2.ListenPort,
		}
		if ps.Hysteria2.MasqueradeURL != "" {
			extra["hysteria2.masquerade_url"] = ps.Hysteria2.MasqueradeURL
		}
		return transport.Options{
			Domain: ps.Domain,
			Email:  ps.Email,
			Extra:  extra,
		}, nil
	case "amneziawg":
		if ps.AmneziaWG == nil {
			return transport.Options{}, errors.New("amneziawg state missing")
		}
		awg := ps.AmneziaWG
		extra := map[string]any{
			"amneziawg.private_key":     awg.ServerPrivateKey,
			"amneziawg.peer_public_key": awg.PeerPublicKey,
			"amneziawg.peer_preshared":  awg.PresharedKey,
			"amneziawg.server_address":  awg.ServerAddress,
			"amneziawg.peer_address":    awg.PeerAddress,
			"amneziawg.listen_port":     awg.ListenPort,
			"amneziawg.mtu":             awg.MTU,
			"amneziawg.dns":             awg.DNS,
			"amneziawg.jc":              awg.Jc,
			"amneziawg.jmin":            awg.Jmin,
			"amneziawg.jmax":            awg.Jmax,
			"amneziawg.s1":              awg.S1,
			"amneziawg.s2":              awg.S2,
			"amneziawg.h1":              awg.H1,
			"amneziawg.h2":              awg.H2,
			"amneziawg.h3":              awg.H3,
			"amneziawg.h4":              awg.H4,
		}
		return transport.Options{
			Domain: ps.Domain,
			Email:  ps.Email,
			Extra:  extra,
		}, nil
	default:
		return transport.Options{}, fmt.Errorf("orchestrator does not know how to configure %q", name)
	}
}

// buildBundle renders the per-client URI bundle from ps. Each
// transport contributes its URI(s) only when the corresponding
// state slice is populated, so home-stealth produces VLESS+Naive,
// home-mobile adds Hysteria2, and home-vpn produces Naive only
// (the AmneziaWG .conf material is rendered into the bundle by
// PR #26 in the Phase 2.2 sequence — until then home-vpn's bundle
// page advertises just the Naive endpoint).
//
// Naive is required: the bundle is served from /sub/<token>/ on
// the Naive listener, so a profile without Naive has no place to
// stage the page.
func buildBundle(ps *ProfileState, now time.Time) (subscribe.Bundle, error) {
	if ps.Naive == nil {
		return subscribe.Bundle{}, errors.New("Naive state required for bundle (it hosts /sub/)")
	}
	bundle := subscribe.Bundle{
		Label:       "xray-aio: " + ps.Domain,
		GeneratedAt: now.UTC().Format(time.RFC3339),
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
	bundle.NaiveURIs = []string{naive}

	if ps.Xray != nil {
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
		bundle.VLESSURIs = []string{vless}
	}
	if ps.Hysteria2 != nil {
		hy2, err := hysteria2transport.RenderURI(hysteria2transport.URIInputs{
			Domain:   ps.Domain,
			Port:     ps.Hysteria2.ListenPort,
			Password: ps.Hysteria2.Password,
			Tag:      ps.Domain + " (Hysteria2)",
		})
		if err != nil {
			return subscribe.Bundle{}, fmt.Errorf("hysteria2 uri: %w", err)
		}
		bundle.Hysteria2URIs = []string{hy2}
	}
	if ps.AmneziaWG != nil {
		entry, err := buildAmneziaWGEntry(ps)
		if err != nil {
			return subscribe.Bundle{}, fmt.Errorf("amneziawg entry: %w", err)
		}
		bundle.AmneziaWGs = []subscribe.AmneziaWGEntry{entry}
	}
	return bundle, nil
}

// awgPeerConfFilename / awgPeerQRFilename are the names of the
// files writeBundle materialises in the bundle dir for the
// AmneziaWG section. Kept as named constants so the HTML's
// relative-URL references and the on-disk write paths agree.
const (
	awgPeerConfFilename = "awg0.conf"
	awgPeerQRFilename   = "awg0.png"
)

// buildAmneziaWGEntry renders the peer-side .conf for the single
// peer ps.AmneziaWG describes and packages it into the
// subscribe.Bundle entry shape. The actual file bytes are
// materialised by writeBundle later — this function only carries
// the strings the HTML page references.
func buildAmneziaWGEntry(ps *ProfileState) (subscribe.AmneziaWGEntry, error) {
	awg := ps.AmneziaWG
	cfg := amneziawgtransport.Config{
		PrivateKey:       awg.ServerPrivateKey,
		PeerPublicKey:    awg.PeerPublicKey,
		PeerPresharedKey: awg.PresharedKey,
		ServerAddress:    awg.ServerAddress,
		PeerAddress:      awg.PeerAddress,
		ListenPort:       awg.ListenPort,
		MTU:              awg.MTU,
		DNS:              awg.DNS,
		Endpoint:         fmt.Sprintf("%s:%d", ps.Domain, awg.ListenPort),
		Obfuscation: amneziawgtransport.Obfuscation{
			Jc:   awg.Jc,
			Jmin: awg.Jmin,
			Jmax: awg.Jmax,
			S1:   awg.S1,
			S2:   awg.S2,
			H1:   awg.H1,
			H2:   awg.H2,
			H3:   awg.H3,
			H4:   awg.H4,
		},
	}
	conf, err := amneziawgtransport.RenderPeer(cfg, awg.PeerPrivateKey, awg.ServerPublicKey)
	if err != nil {
		return subscribe.AmneziaWGEntry{}, fmt.Errorf("render peer: %w", err)
	}
	return subscribe.AmneziaWGEntry{
		Label:        ps.Domain + " (AmneziaWG)",
		Conf:         conf,
		ConfURL:      awgPeerConfFilename,
		ConfFilename: awgPeerConfFilename,
		QRURL:        awgPeerQRFilename,
	}, nil
}

// writeBundle materialises bundle as static files under
// <siteRoot>/sub/<token>/. Returns the bundle directory.
//
// Files produced:
//   - index.html — RenderHTML output, references the relative
//     URLs of the AmneziaWG conf/QR files when present;
//   - plain.txt — RenderPlainText output, URI-only (no AmneziaWG
//     conf — see RenderPlainText doc for rationale);
//   - <conf-filename> + <qr-filename> — one .conf + one .png per
//     AmneziaWG entry (typically awg0.conf + awg0.png in v1).
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
	for _, e := range bundle.AmneziaWGs {
		if err := writeAmneziaWGFiles(dir, e); err != nil {
			return dir, fmt.Errorf("amneziawg files: %w", err)
		}
	}
	return dir, nil
}

// writeAmneziaWGFiles materialises one peer's .conf + QR PNG into
// dir using the relative names embedded in entry.ConfFilename /
// the QRURL convention. The conf carries the peer's private key,
// but Caddy needs to serve it under /sub/<token>/<filename>, so
// the file mode mirrors index.html's 0o644 — the privacy boundary
// is the unguessable subscription token in the URL path, same
// threat model as the URIs sitting in plain.txt next to it.
func writeAmneziaWGFiles(dir string, e subscribe.AmneziaWGEntry) error {
	if e.ConfFilename == "" {
		return errors.New("ConfFilename is empty")
	}
	if err := os.WriteFile(filepath.Join(dir, e.ConfFilename), []byte(e.Conf), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", e.ConfFilename, err)
	}
	if e.QRURL != "" {
		png, err := renderQRPNG(e.Conf)
		if err != nil {
			return fmt.Errorf("render qr: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.QRURL), png, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", e.QRURL, err)
		}
	}
	return nil
}

// renderQRPNG turns the given content into a Medium-EC QR code
// PNG suitable for being scanned by mobile AmneziaWG clients.
// Indirected through a package var so tests can substitute a
// deterministic fake instead of pulling rsc.io/qr's full PNG
// rendering on every assertion.
var renderQRPNG = func(content string) ([]byte, error) {
	code, err := qr.Encode(content, qr.M)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
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
// field. opts is consulted when the default PreflightFn needs to be
// profile-aware — the home-vpn profile, for instance, requires the
// AmneziaWG UDP listen port and /dev/net/tun checks that
// home-stealth and home-mobile do not.
func applyDefaults(opts InstallOptions, d Deps) Deps {
	if d.Rand == nil {
		d.Rand = defaultRand
	}
	if d.PreflightFn == nil {
		d.PreflightFn = defaultPreflightFn(opts)
	}
	if d.NewTransport == nil {
		d.NewTransport = transport.Get
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return d
}

// defaultPreflightFn closes over the install options so the
// preflight suite picks up profile-specific checks (currently:
// AmneziaWG when the profile contains it). Tests that want to
// bypass the standard suite still set Deps.PreflightFn explicitly
// and skip this branch entirely.
func defaultPreflightFn(opts InstallOptions) func(ctx context.Context) (preflight.Result, error) {
	pfOpts := preflight.Options{}
	if profileNeedsAmneziaWG(opts.Profile) {
		port := opts.AmneziaWGListenPort
		if port == 0 {
			port = amneziawgtransport.DefaultListenPort
		}
		pfOpts.AmneziaWGListenPort = port
	}
	return func(ctx context.Context) (preflight.Result, error) {
		return preflight.RunWith(ctx, pfOpts)
	}
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
