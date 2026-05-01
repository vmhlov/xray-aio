package preflight

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	// Run for two ports: 443 (proc-fs hex "01BB", needs zero-padding)
	// and 8444 (proc-fs hex "20FC", already 4-wide). Catches the
	// regression where the parser silently dropped 2-digit-hex ports.
	cases := []struct {
		name string
		port int
		// listenOn picks which proc table the synthetic LISTEN row
		// is written to. Real-world: dual-stack sockets show up
		// in /proc/net/tcp6 only.
		listenOn string
	}{
		{"port-443-tcp6", 443, "tcp6"},
		{"port-8444-tcp4", 8444, "tcp"},
		{"port-80-tcp6", 80, "tcp6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			prevRoot := procRoot
			procRoot = root
			t.Cleanup(func() { procRoot = prevRoot })

			const inode = "999"
			netDir := filepath.Join(root, "net")
			if err := os.MkdirAll(netDir, 0o755); err != nil {
				t.Fatal(err)
			}
			// %04X — match the real kernel's port encoding.
			hexPort := fmt.Sprintf("%04X", tc.port)
			localAddr := "00000000:" + hexPort
			if tc.listenOn == "tcp6" {
				localAddr = "00000000000000000000000000000000:" + hexPort
			}
			tcpRow := "  0: " + localAddr + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0 100 0\n"
			tcpHeader := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			tcpPath := filepath.Join(netDir, "tcp")
			tcp6Path := filepath.Join(netDir, "tcp6")
			tcpContent := tcpHeader
			tcp6Content := tcpHeader
			if tc.listenOn == "tcp6" {
				tcp6Content += tcpRow
			} else {
				tcpContent += tcpRow
			}
			if err := os.WriteFile(tcpPath, []byte(tcpContent), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tcp6Path, []byte(tcp6Content), 0o644); err != nil {
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

			got := lookupPortHolderUnit(tc.port)
			if got != "xray-aio-naive" {
				t.Fatalf("lookupPortHolderUnit(%d) = %q; want xray-aio-naive", tc.port, got)
			}

			// Negative: a port nobody is listening on returns "".
			if got := lookupPortHolderUnit(9999); got != "" {
				t.Fatalf("lookupPortHolderUnit(9999) = %q; want empty", got)
			}
		})
	}
}

func TestCheckAmneziaWGUDPFree(t *testing.T) {
	port := pickFreeUDPPort(t)
	c := checkAmneziaWGUDP(context.Background(), port)
	if c.Status != StatusOK {
		t.Fatalf("status=%s msg=%q; want ok", c.Status, c.Message)
	}
	if c.Name != "amneziawg-udp" {
		t.Errorf("name=%q; want amneziawg-udp", c.Name)
	}
}

func TestCheckAmneziaWGUDPBusyIsHardError(t *testing.T) {
	// AmneziaWG IS the home-vpn data plane: a busy listen port is
	// a hard error (not the soft warn that checkPort443UDP returns
	// for hysteria 2 / quic). Bind a UDP socket ourselves and assert
	// the check surfaces StatusError, not StatusWarn — this is the
	// behavioural contract Install relies on to abort early.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	c := checkAmneziaWGUDP(context.Background(), port)
	if c.Status != StatusError {
		t.Fatalf("status=%s msg=%q; want error (not warn — AmneziaWG cannot fall back)", c.Status, c.Message)
	}
	if !contains(c.Message, "in use") {
		t.Errorf("message=%q; want it to mention `in use`", c.Message)
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
	hexPort := fmt.Sprintf("%04X", port)
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
