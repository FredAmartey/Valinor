package telemetry

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func NewLogger(level, format string, w ...io.Writer) *slog.Logger {
	var writer io.Writer = os.Stderr
	if len(w) > 0 {
		writer = w[0]
	}

	lvl := parseLevel(level)
	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(writer, opts)
	} else {
		handler = slog.NewJSONHandler(writer, opts)
	}

	return slog.New(handler)
}

func SetDefault(logger *slog.Logger) {
	slog.SetDefault(logger)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
