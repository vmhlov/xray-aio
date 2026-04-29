package preflight

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// checkKernel reads /proc/sys/kernel/osrelease and reports the version.
// Anything older than 5.4 is a warning (REALITY/Xray performance suffers).
func checkKernel(_ context.Context) Check {
	v, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return Check{Name: "kernel", Status: StatusWarn, Message: "cannot read kernel version: " + err.Error()}
	}
	ver := strings.TrimSpace(string(v))
	maj, min := parseKernelVersion(ver)
	if maj < 5 || (maj == 5 && min < 4) {
		return Check{Name: "kernel", Status: StatusWarn, Message: fmt.Sprintf("kernel %s is older than 5.4; BBR/HTTP-3 may underperform", ver)}
	}
	return Check{Name: "kernel", Status: StatusOK, Message: ver}
}

// checkBBR verifies that the BBR congestion control algorithm is
// configured. Falls back to a warning if a different algorithm is set
// (cubic, reno, etc.) — xray-aio Phase 1 will offer to enable BBR.
func checkBBR(_ context.Context) Check {
	v, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return Check{Name: "bbr", Status: StatusWarn, Message: "cannot read tcp_congestion_control: " + err.Error()}
	}
	cc := strings.TrimSpace(string(v))
	if cc == "bbr" {
		return Check{Name: "bbr", Status: StatusOK, Message: "tcp_congestion_control=bbr"}
	}
	return Check{Name: "bbr", Status: StatusWarn, Message: fmt.Sprintf("tcp_congestion_control=%s (recommended: bbr)", cc)}
}

// parseKernelVersion extracts <major>.<minor> from a uname-style string
// like "6.8.0-50-generic" → (6, 8). Anything that doesn't parse returns
// (0, 0) so callers downgrade to a warning rather than crash.
func parseKernelVersion(s string) (major, minor int) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	end := 0
	for end < len(parts[1]) && parts[1][end] >= '0' && parts[1][end] <= '9' {
		end++
	}
	if end == 0 {
		return major, 0
	}
	minor, _ = strconv.Atoi(parts[1][:end])
	return major, minor
}
