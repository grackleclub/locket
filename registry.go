package locket

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

/*
Registry is the process by which pre-computed signing keys (ed25519)
are created before deploying either server or client.
	- Public signing keys for all allowed services are provided to the server via .yml
	- Public and private keys are provided to the client for signing requests.
	- Separately, both client and server create encryption keys on startup.
*/

// RegEntry is a single registry item,
// representing a single client which
// the server should recognize and authorize
type RegEntry struct {
	Name   string `yaml:"name"`
	KeyPub string `yaml:"keypub"`
}

// WriteRegistry creates a yaml file with a registry of allowed clients.
func WriteRegistry(path string, data []RegEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	for _, item := range data {
		item.Name = strings.TrimSuffix(filepath.Base(item.Name), ".env")
	}

	b, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	_, err = f.Write(b)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// ReadRegistry turns a yaml file into a list of RegEntry
// for use in server authenticating client requests.
func ReadRegistry(filepath string) ([]RegEntry, error) {
	f, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var out []RegEntry
	err = yaml.Unmarshal(f, &out)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return out, nil
}
