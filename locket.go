package locket

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
)

var Defaults = defaults{
	AllowCird:  "10.0.0.0/24",
	BitsizeRSA: 2048,
}

type defaults struct {
	AllowCird  string // client requests from outside this CIDR are forbidden
	BitsizeRSA int    // bit size passed to RSA creation for client and server encryption
}

// map[serviceName]keyPrivateSigning
type KeysPrivateSigning map[string]string

func init() {
	if testing.Testing() {
		Defaults.AllowCird = "127.0.0.1/32"
	}
	if _, ok := os.LookupEnv("DEBUG"); ok {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Debug("debug logging enabled")
	}
}

// Bootstrap generates a new signing key pair for each service in the provided list.
// Public keys are added to a registry (expected to be written to file),
// and private keys are returned in a map (expected to be provided to clients upon deploy).
func Bootstrap(serviceSecrets map[string][]string) ([]RegEntry, KeysPrivateSigning, error) {
	var registry []RegEntry
	serviceKeysPrivates := make(KeysPrivateSigning)
	for serviceName := range serviceSecrets {
		public, private, err := NewPairEd25519()
		if err != nil {
			return nil, nil, fmt.Errorf("generate key pair: %w", err)
		}
		serviceKeysPrivates[serviceName] = private
		registry = append(registry, RegEntry{
			Name:   serviceName,
			KeyPub: public,
		})
	}
	return registry, serviceKeysPrivates, nil
}
