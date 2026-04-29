package preflight

import (
	"context"
	"net"
	"time"
)

// detectIPDialTimeout is the per-attempt timeout when probing public
// reachability via UDP-dial trick (no packet sent, only routing-table
// resolution).
const detectIPDialTimeout = 2 * time.Second

func checkIPv4(ctx context.Context) Check {
	ip, err := outboundIP(ctx, "udp4", "1.1.1.1:80")
	if err != nil {
		return Check{Name: "ipv4", Status: StatusWarn, Message: "no IPv4 outbound: " + err.Error()}
	}
	return Check{Name: "ipv4", Status: StatusOK, Message: ip.String()}
}

func checkIPv6(ctx context.Context) Check {
	ip, err := outboundIP(ctx, "udp6", "[2606:4700:4700::1111]:80")
	if err != nil {
		return Check{Name: "ipv6", Status: StatusWarn, Message: "no IPv6 outbound (this is fine for Phase 1)"}
	}
	return Check{Name: "ipv6", Status: StatusOK, Message: ip.String()}
}

// outboundIP returns the local address the kernel would pick to reach
// the given remote without actually sending packets.
func outboundIP(ctx context.Context, network, remote string) (net.IP, error) {
	dctx, cancel := context.WithTimeout(ctx, detectIPDialTimeout)
	defer cancel()
	d := net.Dialer{Timeout: detectIPDialTimeout}
	conn, err := d.DialContext(dctx, network, remote)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	la, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errBadAddr
	}
	return la.IP, nil
}

var errBadAddr = &net.AddrError{Err: "unexpected local address type"}
