package locket

import (
	"log/slog"
	"testing"
)

var Defaults = defaults{
	AllowCird:  "10.0.0.0/24",
	BitsizeRSA: 2048,
}

type defaults struct {
	AllowCird  string
	BitsizeRSA int
}

func init() {
	if testing.Testing() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		Defaults.AllowCird = "127.0.0.0/24"
	}
}
