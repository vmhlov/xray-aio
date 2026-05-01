package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/vmhlov/xray-aio/internal/state"
	"github.com/vmhlov/xray-aio/internal/transport"
)

// StatusReport summarises the current install. The CLI's status
// command prints it.
type StatusReport struct {
	Profile         string
	Domain          string
	SubscriptionURL string
	Transports      []TransportStatus
}

// TransportStatus is the per-transport snapshot Status returns.
type TransportStatus struct {
	Name     string
	Status   transport.Status
	Probe    transport.ProbeResult
	StatErr  error
	ProbeErr error
}

// Status returns the current health of the installed profile. Reads
// state.json, then dials each transport's Status + Probe.
func Status(ctx context.Context, deps Deps) (*StatusReport, error) {
	// Status does not run preflight, but applyDefaults still sets
	// Rand / NewTransport / Now. Empty InstallOptions makes the
	// default PreflightFn run the standard suite — never invoked.
	deps = applyDefaults(InstallOptions{}, deps)
	if deps.StatePath != "" {
		// Mirror Install: any explicit override wins.
		if err := setStatePath(deps.StatePath); err != nil {
			return nil, err
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
		return nil, errors.New("no install on this host (state.json has no orchestrator slice)")
	}
	profile, err := ResolveProfile(ps.Profile)
	if err != nil {
		return nil, err
	}
	report := &StatusReport{
		Profile:         ps.Profile,
		Domain:          ps.Domain,
		SubscriptionURL: subscriptionURL(ps),
	}
	for _, name := range profile.Transports {
		ts := TransportStatus{Name: name}
		t, err := deps.NewTransport(name)
		if err != nil {
			ts.StatErr = err
			report.Transports = append(report.Transports, ts)
			continue
		}
		ts.Status, ts.StatErr = t.Status(ctx)
		ts.Probe, ts.ProbeErr = t.Probe(ctx)
		report.Transports = append(report.Transports, ts)
	}
	return report, nil
}

// setStatePath mirrors Install's StatePath handling so callers can
// route Status reads to a t.TempDir() during tests.
func setStatePath(p string) error {
	return os.Setenv(stateEnvVar, p)
}
