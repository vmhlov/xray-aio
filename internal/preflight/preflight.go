// Package preflight runs environmental checks before xray-aio touches the
// system: distro detection, kernel version, free TCP/UDP ports, IPv4/IPv6
// reachability, DNS sanity. Phase 0 ships interfaces and a stub Run() that
// only exercises distro detection.
package preflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Result aggregates all preflight findings. Phase 0 only fills Distro.
type Result struct {
	OS         string
	Arch       string
	Distro     string
	DistroName string
	Warnings   []string
	Errors     []string
}

// Ok reports whether preflight passed without hard errors.
func (r Result) Ok() bool { return len(r.Errors) == 0 }

// Run executes all checks. Currently a placeholder — fleshed out in Phase 1.
func Run(_ context.Context) (Result, error) {
	r := Result{OS: runtime.GOOS, Arch: runtime.GOARCH}
	if r.OS != "linux" {
		r.Errors = append(r.Errors, fmt.Sprintf("unsupported OS: %s (only linux)", r.OS))
	}
	d, name, err := detectDistro()
	if err != nil {
		r.Warnings = append(r.Warnings, "distro detection failed: "+err.Error())
	} else {
		r.Distro, r.DistroName = d, name
	}
	if !r.Ok() {
		return r, errors.New("preflight failed")
	}
	return r, nil
}

// detectDistro parses /etc/os-release and returns ID + PRETTY_NAME.
func detectDistro() (id, pretty string, err error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	if id == "" {
		return "", "", errors.New("ID= not found in /etc/os-release")
	}
	return id, pretty, nil
}
