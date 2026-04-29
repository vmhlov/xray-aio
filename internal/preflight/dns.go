package preflight

import (
	"context"
	"fmt"
	"net"
	"time"
)

// dnsTimeout is the resolution deadline for the DNS sanity probe.
const dnsTimeout = 3 * time.Second

// checkDNS resolves a stable canary host. We do not validate the answer
// — only that the resolver responds within [dnsTimeout]. A failure here
// usually means the system resolver is misconfigured (empty
// /etc/resolv.conf, broken systemd-resolved, captive portal).
func checkDNS(ctx context.Context) Check {
	dctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()
	r := net.Resolver{}
	addrs, err := r.LookupHost(dctx, "one.one.one.one")
	if err != nil {
		return Check{Name: "dns", Status: StatusError, Message: "DNS resolver broken: " + err.Error()}
	}
	if len(addrs) == 0 {
		return Check{Name: "dns", Status: StatusError, Message: "DNS resolver returned 0 addresses"}
	}
	return Check{Name: "dns", Status: StatusOK, Message: fmt.Sprintf("resolver ok (%d addrs)", len(addrs))}
}
