// Package preflight runs environmental checks before xray-aio touches the
// system: distro/arch detection, kernel version + BBR availability, free
// TCP/UDP ports, IPv4/IPv6 reachability, DNS resolver sanity.
//
// Each individual check produces a [Check] entry with one of the
// statuses [StatusOK], [StatusWarn], [StatusError]. [Run] aggregates all
// of them into a [Result]; the orchestrator decides whether to proceed
// based on Result.HasErrors().
package preflight

import (
	"context"
	"errors"
	"runtime"
	"sort"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusOK    Status = "ok"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

// Check is a single named check result.
type Check struct {
	Name    string
	Status  Status
	Message string
}

// Result aggregates all checks executed by Run.
type Result struct {
	OS     string
	Arch   string
	Checks []Check
}

// HasErrors reports whether at least one check failed with [StatusError].
func (r Result) HasErrors() bool {
	for _, c := range r.Checks {
		if c.Status == StatusError {
			return true
		}
	}
	return false
}

// HasWarnings reports whether at least one check produced [StatusWarn].
func (r Result) HasWarnings() bool {
	for _, c := range r.Checks {
		if c.Status == StatusWarn {
			return true
		}
	}
	return false
}

// CheckFunc is a single preflight probe.
type CheckFunc func(ctx context.Context) Check

// defaultChecks is the suite executed by Run. Tests override it via
// [setChecksForTest].
var defaultChecks = []CheckFunc{
	checkOS,
	checkDistro,
	checkKernel,
	checkBBR,
	checkPort80,
	checkPort443TCP,
	checkPort443UDP,
	checkIPv4,
	checkIPv6,
	checkDNS,
}

// Options narrows the preflight suite to a specific install profile.
// Zero value runs the standard suite (every profile gets at least
// the OS / kernel / generic-port / DNS checks).
type Options struct {
	// AmneziaWGListenPort, when > 0, adds two AmneziaWG-specific
	// checks to the suite: the configurable UDP listen port must be
	// free, and /dev/net/tun (or [DevNetTUNPath]) must be a
	// character device openable RDWR. Both surface as hard errors —
	// without them, the home-vpn profile's data plane cannot bind.
	AmneziaWGListenPort int

	// DevNetTUNPath overrides the path checked when
	// AmneziaWGListenPort > 0. Tests under [t.TempDir] use this to
	// drive the negative branches without mucking with the real
	// /dev/net/tun. Empty string falls back to
	// [DefaultDevNetTUNPath].
	DevNetTUNPath string
}

// Run executes the standard preflight suite. Equivalent to
// [RunWith] with the zero [Options].
func Run(ctx context.Context) (Result, error) {
	return RunWith(ctx, Options{})
}

// RunWith executes the standard preflight suite plus any
// profile-specific checks selected by opts. Returned err is
// non-nil whenever the result has any [StatusError] check, even
// when the suite otherwise completed; callers that want to
// downgrade individual failures to warnings should consult
// [Result.HasErrors] instead.
func RunWith(ctx context.Context, opts Options) (Result, error) {
	r := Result{OS: runtime.GOOS, Arch: runtime.GOARCH}
	for _, fn := range defaultChecks {
		r.Checks = append(r.Checks, fn(ctx))
	}
	if opts.AmneziaWGListenPort > 0 {
		r.Checks = append(r.Checks,
			checkAmneziaWGUDP(ctx, opts.AmneziaWGListenPort),
			checkDevNetTUN(opts.DevNetTUNPath),
		)
	}
	sort.SliceStable(r.Checks, func(i, j int) bool { return r.Checks[i].Name < r.Checks[j].Name })
	if r.HasErrors() {
		return r, errors.New("preflight failed")
	}
	return r, nil
}

// checkOS is a non-IO check that fails on non-linux hosts.
func checkOS(_ context.Context) Check {
	if runtime.GOOS != "linux" {
		return Check{Name: "os", Status: StatusError, Message: "unsupported OS: " + runtime.GOOS + " (only linux is supported)"}
	}
	return Check{Name: "os", Status: StatusOK, Message: runtime.GOOS + "/" + runtime.GOARCH}
}
