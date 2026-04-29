// Package transport defines the contract every bypass transport must
// implement so the orchestrator can install/start/stop/probe them
// uniformly. Phase 0 ships the interface and a registry; concrete
// transports (xray, naive, hysteria2, amneziawg, mtproto, singbox) land
// in their own packages in Phase 2.
package transport

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Transport is one bypass implementation (Xray VLESS REALITY, NaïveProxy,
// Hysteria2, AmneziaWG, etc). Each lives in its own subpackage.
type Transport interface {
	// Name is the canonical id used in state.json and CLI flags.
	Name() string

	// Install configures the underlying core (downloads binary, writes
	// config, enables systemd unit). Idempotent.
	Install(ctx context.Context, opts Options) error

	// Start brings the service up.
	Start(ctx context.Context) error

	// Stop tears the service down (without removing config).
	Stop(ctx context.Context) error

	// Status returns current operational state.
	Status(ctx context.Context) (Status, error)

	// Probe runs a transport-specific health check from inside the box.
	Probe(ctx context.Context) (ProbeResult, error)

	// Uninstall removes binaries, config, systemd unit. Cleans state.
	Uninstall(ctx context.Context) error
}

// Options is the bag of common parameters all Install calls accept.
// Transport-specific knobs go into their own option structs and are
// passed through Extra (opaque JSON in state.json).
type Options struct {
	Domain string
	Email  string
	Extra  map[string]any
}

// Status is the result of Transport.Status.
type Status struct {
	Running bool
	PID     int
	Notes   string
}

// ProbeResult is the result of an in-box health check.
type ProbeResult struct {
	OK      bool
	Latency int64 // milliseconds
	Notes   string
}

// registry holds factories keyed by transport name.
var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

// Factory builds a fresh Transport instance.
type Factory func() Transport

// Register adds a factory to the global registry. Called from each
// transport package's init() once it lands in Phase 2.
func Register(name string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("xray-aio/transport: duplicate registration: " + name)
	}
	registry[name] = f
}

// Get returns a fresh Transport by name.
func Get(name string) (Transport, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown transport: %s", name)
	}
	return f(), nil
}

// Names returns the sorted list of registered transports.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
