package locket

import (
	"log/slog"
	"testing"

	logger "github.com/grackleclub/log"
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

var log *slog.Logger

func init() {
	if testing.Testing() {
		Defaults.AllowCIDR = "127.0.0.1/32"
	}

	log, err := logger.New(slog.HandlerOptions{})
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}
	log.Debug("locket logger initialized",
		"allowCIDR", Defaults.AllowCIDR,
		"bitsizeRSA", Defaults.BitsizeRSA,
	)
}
