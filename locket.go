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

// PathRegistry is the API endpoint for registry operations.
//   - GET: list all entries
//   - POST: upsert an entry (RegEntry JSON body)
//   - DELETE: remove an entry (RegEntry JSON body with name)
var PathRegistry = "/locket/registry"

// Environment variable names used by locket clients and servers.
var (
	EnvURL         = "LOCKET_URL"            // locket server URL
	EnvPublic      = "LOCKET_PUBLIC"         // ed25519 public signing key
	EnvPrivate     = "LOCKET_PRIVATE"        // ed25519 private signing key
	EnvRegistryURL = "LOCKET_REGISTRY_URL"   // registry API base URL
	EnvRegistryToken = "LOCKET_REGISTRY_TOKEN" // registry API auth token
)

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
