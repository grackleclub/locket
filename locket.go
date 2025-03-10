package locket

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
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
		slog.SetLogLoggerLevel(slog.LevelDebug)
		Defaults.AllowCird = "127.0.0.0/24"
	}
}

// Bootstrap generates a new key pair for each service in the provided list,
// adding service private keys to a secrets map, and
// public keys with service names to a registry
func Bootstrap(services []string) ([]RegEntry, KeysPrivateSigning, error) {
	var registry []RegEntry
	serviceKeysPrivates := make(KeysPrivateSigning)
	for _, service := range services {
		public, private, err := NewPairEd25519()
		if err != nil {
			return nil, nil, fmt.Errorf("generate key pair: %w", err)
		}
		serviceName := filepath.Base(strings.TrimSuffix(service, filepath.Ext(service)))
		serviceKeysPrivates[serviceName] = private
		registry = append(registry, RegEntry{
			Name:   serviceName,
			KeyPub: public,
		})
	}
	return registry, serviceKeysPrivates, nil
}
