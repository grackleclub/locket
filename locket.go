package locket

import (
	"log/slog"
	"os"
	"testing"
)

var Defaults = defaults{
	AllowCIDR:  "10.0.0.0/24",
	BitsizeRSA: 2048,
}

type defaults struct {
	AllowCIDR  string // client requests from outside this CIDR are forbidden
	BitsizeRSA int    // bit size passed to RSA creation for client and server encryption
}

// map[serviceName]keyPrivateSigning
type KeysPrivateSigning map[string]string

func init() {
	if testing.Testing() {
		Defaults.AllowCIDR = "127.0.0.1/32"
	}
	if _, ok := os.LookupEnv("DEBUG"); ok {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("debug logging enabled")
	}
}
