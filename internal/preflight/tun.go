package preflight

import (
	"errors"
	"fmt"
	"os"
)

// DefaultDevNetTUNPath is the canonical path to the kernel TUN/TAP
// multiplexer device. AmneziaWG (and any userspace WireGuard
// implementation) opens it with TUNSETIFF to materialise its
// in-kernel TUN interface.
const DefaultDevNetTUNPath = "/dev/net/tun"

// checkDevNetTUN verifies that path (defaulting to
// [DefaultDevNetTUNPath] when empty) exists, is a character device,
// and can be opened RDWR. The combination of these three is what a
// userspace TUN-using daemon actually needs at startup; partial
// existence (e.g. node missing because the `tun` kernel module is
// not loaded) shows up as a hard error so the operator notices
// before [Install] tries to start the systemd unit and times out
// waiting for a socket.
//
// The path argument is a test seam — production callers pass "" and
// get [DefaultDevNetTUNPath]; tests under [t.TempDir] pass synthetic
// paths to drive the negative branches.
func checkDevNetTUN(path string) Check {
	if path == "" {
		path = DefaultDevNetTUNPath
	}
	const name = "dev-net-tun"
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Check{
				Name:    name,
				Status:  StatusError,
				Message: fmt.Sprintf("%s: not present (load the tun kernel module: `modprobe tun`)", path),
			}
		}
		return Check{Name: name, Status: StatusError, Message: fmt.Sprintf("%s: stat: %v", path, err)}
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return Check{
			Name:    name,
			Status:  StatusError,
			Message: fmt.Sprintf("%s: not a character device (mode=%s)", path, fi.Mode()),
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if isPermissionDenied(err) && !isRoot() {
			return Check{
				Name:    name,
				Status:  StatusWarn,
				Message: fmt.Sprintf("%s: needs root to open RDWR (re-run as root)", path),
			}
		}
		return Check{Name: name, Status: StatusError, Message: fmt.Sprintf("%s: open RDWR: %v", path, err)}
	}
	_ = f.Close()
	return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("%s available", path)}
}
