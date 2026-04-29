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

// parsePortFromCaddyfile finds the first ":<port> {" site block. Its
// only job is to recover the listen port from a file Render() wrote;
// it is not a full Caddyfile parser.
func parsePortFromCaddyfile(body []byte) (int, error) {
	for _, line := range strings.Split(string(body), "\n") {
		s := strings.TrimSpace(line)
		if !strings.HasPrefix(s, ":") {
			continue
		}
		// Strip trailing "{" and surrounding whitespace.
		s = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(s, "{")), " ")
		s = strings.TrimPrefix(s, ":")
		if s == "" {
			continue
		}
		port, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("bad port %q: %w", s, err)
		}
		if port <= 0 || port > 65535 {
			return 0, fmt.Errorf("port %d out of range", port)
		}
		return port, nil
	}
	return 0, errors.New("no site block found")
}
