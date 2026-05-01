package preflight

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDevNetTUNMissing(t *testing.T) {
	c := checkDevNetTUN(filepath.Join(t.TempDir(), "nope"))
	if c.Status != StatusError {
		t.Fatalf("status=%s msg=%q; want error", c.Status, c.Message)
	}
	if !contains(c.Message, "not present") {
		t.Errorf("message=%q; want it to mention `not present` and `modprobe tun`", c.Message)
	}
	if !contains(c.Message, "modprobe tun") {
		t.Errorf("message=%q; want operator hint about modprobe", c.Message)
	}
}

func TestCheckDevNetTUNNotACharDevice(t *testing.T) {
	// A regular file is the most common false-positive (e.g. an
	// operator who created /dev/net/tun by hand because their
	// kernel module wasn't loaded). The check must reject it
	// rather than letting open(O_RDWR) succeed and pretend the
	// TUN device is usable.
	dir := t.TempDir()
	path := filepath.Join(dir, "tun")
	if err := os.WriteFile(path, []byte("definitely not a TUN"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := checkDevNetTUN(path)
	if c.Status != StatusError {
		t.Fatalf("status=%s msg=%q; want error", c.Status, c.Message)
	}
	if !contains(c.Message, "not a character device") {
		t.Errorf("message=%q; want it to mention `not a character device`", c.Message)
	}
}

func TestCheckDevNetTUNDefaultPath(t *testing.T) {
	// Empty path argument falls back to /dev/net/tun. We do not
	// assert success — running unprivileged in CI sandboxes the
	// open RDWR may be denied, surfaced as a warn — but we DO
	// assert the message mentions the canonical default path so
	// operators see what the check resolved to.
	c := checkDevNetTUN("")
	if !contains(c.Message, DefaultDevNetTUNPath) {
		t.Errorf("message=%q; want mention of %s", c.Message, DefaultDevNetTUNPath)
	}
}

func TestCheckDevNetTUNRealDevice(t *testing.T) {
	// Best-effort positive test: only runs when /dev/net/tun is
	// present and openable RDWR. Skipped in CI sandboxes that lack
	// the TUN module or restrict the device.
	fi, err := os.Stat(DefaultDevNetTUNPath)
	if err != nil {
		t.Skipf("%s not present on this host: %v", DefaultDevNetTUNPath, err)
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s exists but is not a character device", DefaultDevNetTUNPath)
	}
	f, err := os.OpenFile(DefaultDevNetTUNPath, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("%s present but not openable RDWR: %v (typical for unprivileged container)", DefaultDevNetTUNPath, err)
	}
	_ = f.Close()
	c := checkDevNetTUN(DefaultDevNetTUNPath)
	if c.Status != StatusOK {
		t.Fatalf("status=%s msg=%q; want ok", c.Status, c.Message)
	}
}
