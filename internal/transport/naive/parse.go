package naive

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// readSmall reads a file with a hard size cap so a hostile path can't
// blow up memory. The cap covers any sane Caddyfile by orders of
// magnitude.
func readSmall(path string) ([]byte, error) {
	const cap = 1 << 20 // 1 MB
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	body := make([]byte, cap)
	n, err := f.Read(body)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return body[:n], nil
}

// parsePortFromCaddyfile finds the first site block of the form
//
//	[<host>]:<port> {
//
// and returns the port. <host> is optional (Caddy treats a leading
// ':' as "all hosts on that port"); when present, only the colon
// nearest the trailing '{' is treated as the port separator. The
// global '{' block at the top of the file (which has no preceding
// host or port) is skipped.
//
// This is not a full Caddyfile parser; its only job is to recover the
// listen port from a file Render() wrote.
func parsePortFromCaddyfile(body []byte) (int, error) {
	for _, line := range strings.Split(string(body), "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasSuffix(s, "{") {
			continue
		}
		s = strings.TrimSpace(strings.TrimSuffix(s, "{"))
		// Skip the global config block which is just "{"
		if s == "" {
			continue
		}
		// Pick the last ':' as the host:port separator so that
		// IPv6 hosts written as "[::1]:443" or hostnames like
		// "example.com:443" both parse.
		idx := strings.LastIndex(s, ":")
		if idx < 0 {
			// Site block without a port; Caddy infers 443
			// in this case.
			return DefaultListenPort, nil
		}
		portStr := s[idx+1:]
		if portStr == "" {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, fmt.Errorf("bad port %q: %w", portStr, err)
		}
		if port <= 0 || port > 65535 {
			return 0, fmt.Errorf("port %d out of range", port)
		}
		return port, nil
	}
	return 0, errors.New("no site block found")
}
