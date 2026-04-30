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
// Mocked in tests via [setPortHolderUnit].
var portHolderUnit = lookupPortHolderUnit

func lookupPortHolderUnit(port int) string {
	pid, ok := findListeningPID(port)
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

// findListeningPID returns the PID of the process holding a LISTEN
// socket on TCP `port` (any local address, IPv4 or IPv6). Walks
// /proc/net/tcp{,6} for the matching inode, then /proc/<pid>/fd/* to
// resolve which process owns it. Returns (0, false) on any failure.
func findListeningPID(port int) (int, bool) {
	inode, ok := findListeningInode(port)
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

// findListeningInode parses /proc/net/tcp and /proc/net/tcp6 for the
// first row whose local address ends with `:<port>` (in proc-fs's
// uppercase-hex encoding, zero-padded to four nibbles) and whose
// state is 0A (LISTEN). Returns the inode column as a decimal
// string.
func findListeningInode(port int) (string, bool) {
	// Linux formats the port as %04X (e.g. 80 → "0050", 443 →
	// "01BB", 8444 → "20FC"). Match the kernel's width exactly so
	// 2-digit-hex ports are not silently dropped by an
	// unpadded compare.
	hexPort := fmt.Sprintf("%04X", port)
	for _, path := range []string{
		filepath.Join(procRoot, "net", "tcp"),
		filepath.Join(procRoot, "net", "tcp6"),
	} {
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
			localAddr := fields[1]
			state := fields[3]
			if state != "0A" {
				continue
			}
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

// procRoot is the root used by [findListeningPID] /
// [readSystemdUnit] when reading proc-fs. Overridable in tests via
// [setProcRoot].
var procRoot = "/proc"
