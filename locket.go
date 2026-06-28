package locket

import (
	"log/slog"
	"testing"
	"time"

	logger "github.com/grackleclub/log"
)

var Defaults = defaults{
	AllowCIDR:    "10.0.0.0/24",
	BitsizeRSA:   2048,
	MaxClockSkew: 30 * time.Second,
}

type defaults struct {
	AllowCIDR    string        // client requests from outside this CIDR are forbidden
	BitsizeRSA   int           // bit size passed to RSA creation for client and server encryption
	MaxClockSkew time.Duration // max client/server clock difference before a request is rejected
}

// PathRegistry is the API endpoint for registry operations.
//   - GET: list all entries
//   - POST: upsert an entry (RegEntry JSON body)
//   - DELETE: remove an entry (RegEntry JSON body with name)
var PathRegistry = "/locket/registry"

// map[serviceName]keyPrivateSigning
type KeysPrivateSigning map[string]string

var log *slog.Logger

func init() {
	var opts slog.HandlerOptions
	if testing.Testing() {
		Defaults.AllowCIDR = "127.0.0.1/32"
		opts.Level = slog.LevelDebug
		opts.AddSource = true
	}

	var err error
	log, err = logger.New(opts)
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}
	log.Debug("locket logger initialized",
		"allowCIDR", Defaults.AllowCIDR,
		"bitsizeRSA", Defaults.BitsizeRSA,
	)
}
