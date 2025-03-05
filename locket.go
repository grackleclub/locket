package locket

import (
	"log/slog"
	"testing"
)

func init() {
	if testing.Testing() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
}
