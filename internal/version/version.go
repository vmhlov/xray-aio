// Package version exposes build metadata injected via -ldflags.
package version

// These are populated at build time via -ldflags. Defaults are used in
// `go run` and `go test` so callers always get a non-empty string.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)
