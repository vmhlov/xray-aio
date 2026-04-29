package preflight

import (
	"context"
	"net"
	"testing"
)

func TestCheckTCPPortFree(t *testing.T) {
	// Use an unprivileged port so the test does not require root.
	port := pickFreePort(t)
	c := checkTCPPort(context.Background(), port, "test")
	if c.Status != StatusOK {
		t.Fatalf("expected ok, got %s: %s", c.Status, c.Message)
	}
}

func TestCheckTCPPortBusy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	c := checkTCPPort(context.Background(), port, "test")
	if c.Status != StatusError {
		// On hosts where the kernel allows REUSEADDR-shadow this can
		// race — accept either error or warn but not OK.
		if c.Status == StatusOK {
			t.Fatalf("expected error/warn, got ok: %s", c.Message)
		}
	}
}

func TestCheckUDPPortFree(t *testing.T) {
	port := pickFreeUDPPort(t)
	c := checkUDPPort(context.Background(), port, "test")
	if c.Status != StatusOK {
		t.Fatalf("expected ok, got %s: %s", c.Status, c.Message)
	}
}

func TestCheckTCPPortPermissionDenied(t *testing.T) {
	if isRoot() {
		t.Skip("running as root; cannot exercise EACCES path")
	}
	c := checkTCPPort(context.Background(), 80, "test")
	if c.Status != StatusWarn {
		t.Fatalf("expected warn (EACCES on non-root for port 80), got %s: %s", c.Status, c.Message)
	}
}

func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func pickFreeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}
