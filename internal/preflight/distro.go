package preflight

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// supportedDistros lists IDs from /etc/os-release that we test against.
// Other distros only produce a warning — the user is free to try.
var supportedDistros = map[string]bool{
	"debian":              true,
	"ubuntu":              true,
	"alpine":              true,
	"rocky":               true,
	"almalinux":           true,
	"centos":              true,
	"rhel":                true,
	"fedora":              true,
	"arch":                true,
	"opensuse":            true,
	"opensuse-leap":       true,
	"opensuse-tumbleweed": true,
}

func checkDistro(_ context.Context) Check {
	id, pretty, err := readOSRelease("/etc/os-release")
	if err != nil {
		return Check{Name: "distro", Status: StatusWarn, Message: "cannot detect distro: " + err.Error()}
	}
	msg := fmt.Sprintf("%s (%s)", id, pretty)
	if !supportedDistros[id] {
		return Check{Name: "distro", Status: StatusWarn, Message: msg + " — not in tested matrix"}
	}
	return Check{Name: "distro", Status: StatusOK, Message: msg}
}

// readOSRelease parses ID= and PRETTY_NAME= from an os-release-formatted
// file. Exposed (lower-case) for direct test access.
func readOSRelease(path string) (id, pretty string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "ID":
			id = v
		case "PRETTY_NAME":
			pretty = v
		}
	}
	if id == "" {
		return "", "", errors.New("ID= not found in " + path)
	}
	return id, pretty, nil
}
