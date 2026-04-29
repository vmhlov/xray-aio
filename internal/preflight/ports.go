package preflight

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

// We probe the ports xray-aio plans to bind during Phase 1 install
// (TCP 80/443 for ACME + REALITY, UDP 443 only for QUIC transports
// such as Hysteria 2). Probing means opening a listener on the
// wildcard address and immediately closing it. EADDRINUSE → error;
// EACCES on a non-root run → warn (we cannot tell if the port is busy
// without privilege).

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
