package preflight

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	// portHolderUnit returns "" by default outside of our service —
	// an arbitrary `net.Listen` busy port should NOT match our unit
	// prefix. Stub it explicitly so this test does not depend on the
	// host's /proc state.
	prev := portHolderUnit
	portHolderUnit = func(int) string { return "" }
	t.Cleanup(func() { portHolderUnit = prev })

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

func TestCheckTCPPortHeldByOurUnitDowngradesToOK(t *testing.T) {
	prev := portHolderUnit
	portHolderUnit = func(port int) string { return "xray-aio-naive" }
	t.Cleanup(func() { portHolderUnit = prev })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	c := checkTCPPort(context.Background(), port, "test")
	if c.Status != StatusOK {
		t.Fatalf("expected ok (held by our unit), got %s: %s", c.Status, c.Message)
	}
	if !contains(c.Message, "xray-aio-naive") || !contains(c.Message, "steady state") {
		t.Fatalf("expected message to mention unit + steady state, got %q", c.Message)
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

func TestLookupPortHolderUnitWithFakeProc(t *testing.T) {
	// Build a fake /proc layout:
	//   /proc/net/tcp        — single LISTEN row on port 8444 inode 999
	//   /proc/12345/fd/3     — symlink to "socket:[999]"
	//   /proc/12345/cgroup   — cgroup path containing xray-aio-naive.service
	root := t.TempDir()
	prevRoot := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = prevRoot })

	const port = 8444
	const inode = "999"
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Port 8444 in proc-fs hex (uppercase, no padding) is 20FC.
	hexPort := strconv.FormatInt(port, 16)
	hexPort = upper(hexPort)
	tcpRow := "  0: 00000000:" + hexPort + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0 100 0\n"
	tcpHeader := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpHeader+tcpRow), 0o644); err != nil {
		t.Fatal(err)
	}
	// Empty tcp6 — exercises the "skip empty file" branch.
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(tcpHeader), 0o644); err != nil {
		t.Fatal(err)
	}

	pidDir := filepath.Join(root, "12345")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"),
		[]byte("0::/system.slice/xray-aio-naive.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := lookupPortHolderUnit(port)
	if got != "xray-aio-naive" {
		t.Fatalf("lookupPortHolderUnit(%d) = %q; want xray-aio-naive", port, got)
	}

	// Negative: a port nobody is listening on returns "".
	if got := lookupPortHolderUnit(9999); got != "" {
		t.Fatalf("lookupPortHolderUnit(9999) = %q; want empty", got)
	}
}

func TestLookupPortHolderUnitForeignServiceReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	prevRoot := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = prevRoot })

	const port = 80
	const inode = "1234"
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hexPort := upper(strconv.FormatInt(port, 16))
	tcpRow := "  0: 00000000:" + hexPort + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0 100 0\n"
	tcpHeader := "  sl  local_address rem_address   st\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcpHeader+tcpRow), 0o644); err != nil {
		t.Fatal(err)
	}

	pidDir := filepath.Join(root, "555")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(fdDir, "5")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"),
		[]byte("0::/system.slice/nginx.service\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := lookupPortHolderUnit(port); got != "" {
		t.Fatalf("expected empty for foreign service, got %q", got)
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

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}
