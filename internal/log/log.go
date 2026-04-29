// Package log is a thin wrapper over log/slog with sensible defaults
// (text format on stderr, level from XRAY_AIO_LOG=debug|info|warn|error).
package log

import (
	"log/slog"
	"os"
	"strings"
)

var logger *slog.Logger

func init() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("XRAY_AIO_LOG")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// L returns the package logger.
func L() *slog.Logger { return logger }
