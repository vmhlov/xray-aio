package preflight

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// We probe the ports xray-aio plans to bind during Phase 1 install
// (TCP 80/443 for ACME + REALITY, UDP 443 only for QUIC transports
// such as Hysteria 2). Probing means opening a listener on the
// wildcard address and immediately closing it. EADDRINUSE → error;
// EACCES on a non-root run → warn (we cannot tell if the port is busy
// without privilege).

// ourUnitPrefix is the prefix every systemd unit xray-aio writes
// shares. When a TCP port is busy and the listening process belongs
// to a unit with this prefix, the port is considered "held by us"
// (steady state, not a conflict) and the check downgrades to OK.
const ourUnitPrefix = "xray-aio-"

func checkPort80(ctx context.Context) Check {
	return checkTCPPort(ctx, 80, "port-80-tcp")
}

func checkPort443TCP(ctx context.Context) Check {
	return checkTCPPort(ctx, 443, "port-443-tcp")
}

func checkPort443UDP(ctx context.Context) Check {
	return checkUDPPort(ctx, 443, "port-443-udp")
}

func checkTCPPort(ctx context.Context, port int, name string) Check {
	addr := net.JoinHostPort("", strconv.Itoa(port))
	lc := net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		if isPermissionDenied(err) && !isRoot() {
			return Check{Name: name, Status: StatusWarn, Message: fmt.Sprintf("tcp/%d: needs root to probe (re-run as root)", port)}
		}
		if unit := portHolderUnit(port); unit != "" {
			return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("tcp/%d held by %s (steady state)", port, unit)}
		}
		return Check{Name: name, Status: StatusError, Message: fmt.Sprintf("tcp/%d in use: %v", port, err)}
	}
	_ = l.Close()
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("tcp/%d free", port)}
}

func checkUDPPort(ctx context.Context, port int, name string) Check {
	addr := net.JoinHostPort("", strconv.Itoa(port))
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		if isPermissionDenied(err) && !isRoot() {
			return Check{Name: name, Status: StatusWarn, Message: fmt.Sprintf("udp/%d: needs root to probe (re-run as root)", port)}
		}
		// UDP/443 busy is a soft warning: Hysteria 2/QUIC are optional
		// transports and not part of the default home-stealth profile.
		return Check{Name: name, Status: StatusWarn, Message: fmt.Sprintf("udp/%d in use: %v (only needed for QUIC transports)", port, err)}
	}
	_ = pc.Close()
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("udp/%d free", port)}
}

// checkAmneziaWGUDP probes the configurable AmneziaWG listen port.
// Unlike [checkPort443UDP] (where UDP 443 is optional / Hysteria 2),
// AmneziaWG IS the home-vpn profile's data plane — a busy port is a
// hard error so [Install] does not silently land in a state where
// systemd boots the unit but the kernel rejects bind().
//
// Re-install case: when the operator runs Install on an already
// configured host, our own xray-aio-amneziawg unit is still holding
// the port (Phase 3 restart has not happened yet). Mirror the TCP
// path's [portHolderUnit] escape hatch so the steady-state
// re-install does not abort here on EADDRINUSE — see [udpPortHolderUnit].
func checkAmneziaWGUDP(ctx context.Context, port int) Check {
	const name = "amneziawg-udp"
	addr := net.JoinHostPort("", strconv.Itoa(port))
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", addr)
	if err != nil {
		if isPermissionDenied(err) && !isRoot() {
			return Check{Name: name, Status: StatusWarn, Message: fmt.Sprintf("udp/%d: needs root to probe (re-run as root)", port)}
		}
		if unit := udpPortHolderUnit(port); unit != "" {
			return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("udp/%d held by %s (steady state)", port, unit)}
		}
		return Check{Name: name, Status: StatusError, Message: fmt.Sprintf("udp/%d in use: %v", port, err)}
	}
	_ = pc.Close()
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("udp/%d free", port)}
}

// isRoot is mocked in tests via [setIsRoot].
var isRoot = func() bool { return os.Geteuid() == 0 }

func isPermissionDenied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission)
}

// portHolderUnit returns the name of the systemd unit currently
// listening on TCP port `port` if (and only if) that unit's name
// begins with [ourUnitPrefix]. Returns "" otherwise — port not held
// by us, port not held by any systemd unit at all, or detection
// failed (non-Linux host, missing /proc, no permission). Best-effort:
// every failure mode returns "" rather than surfacing an error, so
// callers fall through to the normal EADDRINUSE → StatusError path.
//
// Mocked in tests via direct assignment.
var portHolderUnit = func(port int) string { return lookupHolderUnit(port, "tcp") }

// udpPortHolderUnit is the UDP-side counterpart used by
// [checkAmneziaWGUDP] so a re-install does not flag our own running
// xray-aio-amneziawg as a foreign port conflict. Same fail-closed
// contract as [portHolderUnit].
var udpPortHolderUnit = func(port int) string { return lookupHolderUnit(port, "udp") }

func lookupHolderUnit(port int, proto string) string {
	pid, ok := findHolderPID(port, proto)
	if !ok {
		return ""
	}
	unit, ok := readSystemdUnit(pid)
	if !ok {
		return ""
	}
	if !strings.HasPrefix(unit, ourUnitPrefix) {
		return ""
	}
	return unit
}

// findHolderPID returns the PID of the process holding a socket on
// `port` for the given proto ("tcp" or "udp"). Walks the appropriate
// /proc/net/<proto>{,6} table for the matching inode, then
// /proc/<pid>/fd/* to resolve which process owns it. Returns
// (0, false) on any failure.
func findHolderPID(port int, proto string) (int, bool) {
	inode, ok := findHolderInode(port, proto)
	if !ok {
		return 0, false
	}
	procEntries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, false
	}
	target := "socket:[" + inode + "]"
	for _, e := range procEntries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			// EACCES on processes we don't own — skip silently.
			continue
		}
		for _, fd := range fdEntries {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid, true
			}
		}
	}
	return 0, false
}

// findHolderInode parses /proc/net/<proto> and /proc/net/<proto>6
// for the first row whose local address ends with `:<port>` (in
// proc-fs's uppercase-hex encoding, zero-padded to four nibbles).
// Returns the inode column as a decimal string.
//
// For TCP we additionally require state "0A" (LISTEN) so half-open /
// established sockets to the same port do not match. UDP is
// stateless — the kernel reuses TCP state values and a bound but
// unconnected socket reports "07" (TCP_CLOSE) — so we accept any
// state for UDP.
func findHolderInode(port int, proto string) (string, bool) {
	var stateFilter string
	if proto == "tcp" {
		stateFilter = "0A"
	}
	// Linux formats the port as %04X (e.g. 80 → "0050", 443 →
	// "01BB", 8444 → "20FC"). Match the kernel's width exactly so
	// 2-digit-hex ports are not silently dropped by an
	// unpadded compare.
	hexPort := fmt.Sprintf("%04X", port)
	for _, suffix := range []string{"", "6"} {
		path := filepath.Join(procRoot, "net", proto+suffix)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		// Skip header line.
		_ = scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			// Expected layout: sl  local_address  rem_address  st  ...  inode  ...
			if len(fields) < 10 {
				continue
			}
			if stateFilter != "" && fields[3] != stateFilter {
				continue
			}
			localAddr := fields[1]
			colon := strings.LastIndex(localAddr, ":")
			if colon < 0 {
				continue
			}
			if !strings.EqualFold(localAddr[colon+1:], hexPort) {
				continue
			}
			_ = f.Close()
			return fields[9], true
		}
		_ = f.Close()
	}
	return "", false
}

// readSystemdUnit returns the systemd unit name from /proc/<pid>/cgroup
// if the cgroup path contains `<unit>.service`. systemd writes service
// cgroups as `0::/system.slice/<unit>.service` (cgroup v2) or
// `…:name=systemd:/system.slice/<unit>.service` (v1) — both forms
// contain the unit's basename, which is what we extract.
func readSystemdUnit(pid int) (string, bool) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		// Find the last `/` and the closing `.service`.
		idx := strings.LastIndex(line, "/")
		if idx < 0 {
			continue
		}
		base := line[idx+1:]
		if !strings.HasSuffix(base, ".service") {
			continue
		}
		return strings.TrimSuffix(base, ".service"), true
	}
	return "", false
}

// procRoot is the root used by [findHolderPID] / [readSystemdUnit]
// when reading proc-fs. Overridable in tests via direct
// assignment.
var procRoot = "/proc"
